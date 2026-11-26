import { niceTicks } from "./LineChart";
import { perPoll, topFailedIps } from "../sections/SshSection";
import type { SshSnapshot } from "../api";

test("niceTicks steps by 1, 2 or 5 x 10^k and covers the max", () => {
  expect(niceTicks(0)).toEqual([0, 0.5, 1]);
  expect(niceTicks(7)).toEqual([0, 2, 4, 6, 8]);
  expect(niceTicks(130)).toEqual([0, 50, 100, 150]);
});

test("perPoll turns running totals into increases, unknown after a restart", () => {
  expect(perPoll([3, 5, 5, 9, 2, 4])).toEqual([null, 2, 0, 4, null, 2]);
});

test("topFailedIps ranks addresses by failed logins only", () => {
  const login = (kind: SshSnapshot["recent_logins"][number]["kind"], ip: string) => ({
    at: "",
    kind,
    user: "u",
    ip,
    port: 1,
    pid: 1,
    method: null,
  });
  const snap = {
    recent_logins: [
      login("login_failure", "a"),
      login("invalid_user", "b"),
      login("login_failure", "b"),
      login("login_success", "a"),
      login("login_success", "c"),
    ],
  } as SshSnapshot;
  expect(topFailedIps(snap)).toEqual([
    { label: "b", value: 2 },
    { label: "a", value: 1 },
  ]);
});
