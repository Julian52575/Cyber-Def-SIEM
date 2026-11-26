import { act, fireEvent, render, screen, within } from "@testing-library/react";
import App, { DEFAULT_API_URL, parseApiUrl } from "./App";
import type { SshSnapshot } from "./api";

const SNAPSHOT: SshSnapshot = {
  started_at: "2026-11-26T10:00:00+00:00",
  uptime: 3725,
  config: { ports: [22], window: 60 },
  sources: {
    sshd_log: { status: "running", detail: "/var/log/auth.log" },
    network: { status: "failed", detail: "permission denied" },
  },
  counts: { login_success: 3, login_failure: 4, invalid_user: 1, conn_opened: 5, alerts: 1 },
  active_connections: [
    {
      client_ip: "10.0.0.5",
      client_port: 50122,
      server_ip: "10.0.0.1",
      server_port: 22,
      started: "2026-11-26T10:59:00+00:00",
      packets: 40,
      bytes: 4096,
      duration: 60,
    },
  ],
  recent_logins: [
    { at: "2026-11-26T11:00:00+00:00", kind: "login_failure", user: "root", ip: "203.0.113.9", port: 4242, pid: 90, method: "password" },
  ],
  recent_alerts: [
    { at: "2026-11-26T11:00:01+00:00", name: "ssh_bruteforce", ip: "203.0.113.9", message: "203.0.113.9 made 5 failed ssh logins within 60s" },
  ],
};

function typeAddress(value: string) {
  fireEvent.change(screen.getByLabelText("SIEM API address"), { target: { value } });
}

const healthButton = () => screen.getByRole("button", { name: "Health check" });
const pollButton = () => screen.getByRole("button", { name: /polling/ });

function stubApi() {
  const fetchMock = vi.fn((url: string) =>
    Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(url.endsWith("/ssh") ? SNAPSHOT : {}) }),
  );
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

describe("parseApiUrl", () => {
  test("accepts http(s) and strips the trailing slash", () => {
    expect(parseApiUrl(" http://10.0.0.5:8000/ ")).toBe("http://10.0.0.5:8000");
    expect(parseApiUrl("https://siem.lan/api")).toBe("https://siem.lan/api");
  });

  test("rejects anything else", () => {
    expect(parseApiUrl("10.0.0.5:8000")).toBeNull();
    expect(parseApiUrl("ftp://siem.lan")).toBeNull();
    expect(parseApiUrl("not a url")).toBeNull();
  });
});

describe("health check", () => {
  beforeEach(() => localStorage.clear());

  test("defaults to the local SIEM API", () => {
    render(<App />);
    expect(screen.getByLabelText("SIEM API address")).toHaveValue(DEFAULT_API_URL);
    expect(DEFAULT_API_URL).toBe("http://127.0.0.1:12125");
  });
  afterEach(() => vi.unstubAllGlobals());

  test("does not call the API until a button is pressed", () => {
    const fetchMock = stubApi();
    render(<App />);
    typeAddress("http://10.0.0.5:8000");
    expect(screen.getByText("not checked")).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test("disables the buttons for an empty or invalid address", () => {
    render(<App />);
    typeAddress("");
    expect(healthButton()).toBeDisabled();
    expect(pollButton()).toBeDisabled();
    typeAddress("10.0.0.5:8000");
    expect(healthButton()).toBeDisabled();
    expect(screen.getByText("Enter an http:// or https:// address.")).toBeInTheDocument();
  });

  test("calls /healthz on the typed address and shows ok", async () => {
    const fetchMock = stubApi();
    render(<App />);
    typeAddress("http://10.0.0.5:8000/");
    fireEvent.click(healthButton());
    expect(await screen.findByText("ok")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith("http://10.0.0.5:8000/healthz");
  });

  test("shows unreachable on a failed request", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("down")));
    render(<App />);
    typeAddress("http://10.0.0.5:8000");
    fireEvent.click(healthButton());
    expect(await screen.findByText("unreachable")).toBeInTheDocument();
  });

  test("remembers the address across reloads", () => {
    const { unmount } = render(<App />);
    typeAddress("http://10.0.0.5:8000");
    unmount();
    render(<App />);
    expect(screen.getByLabelText("SIEM API address")).toHaveValue("http://10.0.0.5:8000");
  });
});

describe("polling", () => {
  beforeEach(() => localStorage.clear());
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  test("polls /ssh and fills the SSH section", async () => {
    const fetchMock = stubApi();
    render(<App />);
    expect(screen.getByText(/No data yet/)).toBeInTheDocument();
    typeAddress("http://10.0.0.5:8000");
    fireEvent.click(pollButton());

    expect(await screen.findByText("1h 2m")).toBeInTheDocument(); // uptime tile
    expect(fetchMock).toHaveBeenCalledWith("http://10.0.0.5:8000/ssh", expect.anything());
    expect(pollButton()).toHaveTextContent("Stop polling");
    expect(screen.getByText("sshd logs")).toBeInTheDocument();
    expect(screen.getAllByText("203.0.113.9").length).toBeGreaterThan(0);
    expect(screen.getByRole("img", { name: "Active SSH connections diagram" })).toBeInTheDocument();
  });

  test("polls again after the interval and stops on demand", async () => {
    vi.useFakeTimers();
    const fetchMock = stubApi();
    render(<App />);
    typeAddress("http://10.0.0.5:8000");
    fireEvent.click(pollButton());
    await act(() => vi.advanceTimersByTimeAsync(0));
    expect(fetchMock).toHaveBeenCalledTimes(1);

    await act(() => vi.advanceTimersByTimeAsync(5000));
    expect(fetchMock).toHaveBeenCalledTimes(2);

    fireEvent.click(pollButton());
    await act(() => vi.advanceTimersByTimeAsync(20000));
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  test("keeps the last data and shows the error when a poll fails", async () => {
    vi.useFakeTimers();
    const fetchMock = stubApi();
    render(<App />);
    typeAddress("http://10.0.0.5:8000");
    fireEvent.click(pollButton());
    await act(() => vi.advanceTimersByTimeAsync(0));

    fetchMock.mockRejectedValueOnce(new Error("connection refused"));
    await act(() => vi.advanceTimersByTimeAsync(5000));
    expect(screen.getByText(/Last poll failed: connection refused/)).toBeInTheDocument();
    expect(screen.getByText("1h 2m")).toBeInTheDocument();
  });

  test("changing the address stops polling and clears the data", async () => {
    stubApi();
    render(<App />);
    typeAddress("http://10.0.0.5:8000");
    fireEvent.click(pollButton());
    await screen.findByText("1h 2m");
    typeAddress("http://10.0.0.6:8000");
    expect(pollButton()).toHaveTextContent("Start polling");
    expect(screen.queryByText("1h 2m")).not.toBeInTheDocument();
  });
});

describe("sections", () => {
  beforeEach(() => localStorage.clear());

  test("the dummy section shows placeholder charts without any API call", () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);
    fireEvent.click(screen.getByRole("tab", { name: /Dummy/ }));
    const panel = screen.getByRole("tabpanel");
    expect(within(panel).getByText("dummy data")).toBeInTheDocument();
    expect(within(panel).getByRole("img", { name: "Events per hour" })).toBeInTheDocument();
    expect(within(panel).getByText("Detections by rule")).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });
});
