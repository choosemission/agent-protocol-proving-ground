/**
 * Runs and attempts, in SQLite. A run is one handle across every door. An
 * attempt belongs to one door; it starts when the door challenges
 * (it owns the nonce it was issued) and climbs the ladder on retry.
 *
 * Stored per attempt: the run, the highest step reached, the request mode
 * answered, the stop code and reason, and a timeline of the exchange in
 * plain words. Never stored: credentials, presentations, disclosed values,
 * IP addresses, run IDs in anything public.
 */
import { randomBytes } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { DATA_DIR } from './lab.ts';

export type Entry = { at: string; text: string; step?: string; ok?: boolean };
export type Attempt = {
  id: string;
  run_id: string | null;
  nonce: string | null;
  nonce_expires: number | null;
  nonce_used: number;
  step: number;
};

mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(process.env.DB_PATH ?? join(DATA_DIR, 'proving-ground.db'));
db.exec(`
  create table if not exists runs (
    id text primary key,
    handle text not null unique,
    created_at text not null
  );
  create table if not exists attempts (
    id text primary key,
    run_id text references runs(id),
    door text not null,
    nonce text unique,
    nonce_expires integer,
    nonce_used integer not null default 0,
    step integer not null,
    mode text,
    error text,
    reason text,
    timeline text not null default '[]',
    created_at text not null,
    updated_at text not null
  );
`);

/** Fires 'change' after every write, for the wall's live feed. */
export const bus = new EventEmitter();
const now = () => new Date().toISOString();
const id = (bytes: number) => randomBytes(bytes).toString('base64url');

export function createRun(handle: string) {
  const run = { id: id(16), handle, created_at: now() };
  db.prepare('insert into runs (id, handle, created_at) values (?, ?, ?)').run(run.id, run.handle, run.created_at);
  bus.emit('change');
  return run;
}

export const runExists = (runId: string) => !!db.prepare('select 1 from runs where id = ?').get(runId);
export const handleOf = (runId: string) => (db.prepare('select handle from runs where id = ?').get(runId) as { handle: string } | undefined)?.handle ?? null;
export const handleTaken =(handle: string) => !!db.prepare('select 1 from runs where handle = ?').get(handle);

export function newAttempt(a: { door: string; runId: string | null; nonce: string | null; nonceExpires: number | null; step: number; timeline: Entry[] }) {
  const attemptId = id(9);
  const t = now();
  db.prepare(
    `insert into attempts (id, run_id, door, nonce, nonce_expires, step, timeline, created_at, updated_at)
     values (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(attemptId, a.runId, a.door, a.nonce, a.nonceExpires, a.step, JSON.stringify(a.timeline), t, t);
  bus.emit('change');
  return attemptId;
}

export const attemptByNonce = (nonce: string) =>
  db.prepare('select id, run_id, nonce, nonce_expires, nonce_used, step from attempts where nonce = ?').get(nonce) as
    | Attempt
    | undefined;

/** Marks a nonce spent. Returns false if it already was (a concurrent replay). */
export const spendNonce = (attemptId: string) =>
  db.prepare('update attempts set nonce_used = 1 where id = ? and nonce_used = 0').run(attemptId).changes === 1;

export function finishAttempt(attemptId: string, r: { step: number; mode: string | null; error: string | null; reason: string | null; more: Entry[] }) {
  const row = db.prepare('select timeline from attempts where id = ?').get(attemptId) as { timeline: string };
  const timeline = [...(JSON.parse(row.timeline) as Entry[]), ...r.more];
  db.prepare('update attempts set step = max(step, ?), mode = ?, error = ?, reason = ?, timeline = ?, updated_at = ? where id = ?').run(
    r.step, r.mode, r.error, r.reason, JSON.stringify(timeline), now(), attemptId,
  );
  bus.emit('change');
}

/** One attempt's public timeline, by attempt ID. Shows the handle, never the run ID. */
export function attemptDetail(attemptId: string) {
  const row = db
    .prepare(
      `select a.id, a.door, r.handle, a.step, a.mode, a.error, a.reason, a.timeline, a.created_at, a.updated_at
       from attempts a left join runs r on r.id = a.run_id where a.id = ?`,
    )
    .get(attemptId) as Record<string, unknown> | undefined;
  return row && { ...row, timeline: JSON.parse(row.timeline as string) as Entry[] };
}

/** Everything the wall shows for one door, in one read. */
export function wallState(door: string, throughStep: number) {
  const all = (sql: string, ...p: (string | number)[]) => db.prepare(sql).all(...p);
  const counts = all('select step, count(*) n from attempts where door = ? group by step', door) as { step: number; n: number }[];
  return {
    runs: all(
      `select r.handle, coalesce(max(a.step), -1) step, count(a.id) attempts
       from runs r left join attempts a on a.run_id = r.id and a.door = ?
       group by r.id order by step desc, r.created_at`,
      door,
    ),
    anon: db.prepare('select coalesce(max(step), -1) step, count(*) attempts from attempts where run_id is null and door = ?').get(door),
    first: db
      .prepare(
        `select coalesce(r.handle, 'anon') handle, a.updated_at at from attempts a left join runs r on r.id = a.run_id
         where a.door = ? and a.step = ? order by a.updated_at limit 1`,
      )
      .get(door, throughStep) ?? null,
    recent: all(
      `select a.id, coalesce(r.handle, 'anon') handle, a.step, a.error, a.updated_at at
       from attempts a left join runs r on r.id = a.run_id where a.door = ? order by a.updated_at desc limit 15`,
      door,
    ),
    // reached[i] = attempts that got at least as far as step i
    reached: Array.from({ length: throughStep + 1 }, (_, i) => counts.filter((c) => c.step >= i).reduce((s, c) => s + c.n, 0)),
    stopped: all('select error, count(*) n from attempts where door = ? and error is not null group by error order by n desc', door),
  };
}
