import Foundation
import Testing
import CSQLite
import SwiftOAuthCore
@testable import SwiftOAuthProvider

/// Head-of-line blocking inside one process.
///
/// `OAuthStorage` is an actor and every method is synchronous, so concurrent calls run one
/// after another on the actor, each blocking in `sqlite3_step` for the busy timeout when
/// another connection holds the lock. Measured in a real run, a 20 s lock made the N-th
/// concurrent request wait about N x 5 s, outlasting any client or proxy timeout. The calls
/// queued behind a timed-out one share its verdict: the lock was held when the wait ended.
@Suite("OAuth storage — calls queued behind a busy lock")
struct OAuthStorageBusyStackingTests {

    typealias Rival = OAuthStorageBusyTests.Rival
    static let callers = 4

    /// Runs `callers` concurrent saves; returns each one's outcome and the elapsed seconds.
    static func burst(_ storage: OAuthStorage, tag: String) async -> (failures: Int, busy: Int, elapsed: Double) {
        let start = ProcessInfo.processInfo.systemUptime
        let outcomes = await withTaskGroup(of: Result<Void, Error>.self) { group in
            for index in 0..<callers {
                group.addTask {
                    do {
                        try await storage.saveClient(OAuthStorageBusyTests.client("\(tag)-\(index)"))
                        return .success(())
                    } catch { return .failure(error) }
                }
            }
            var all: [Result<Void, Error>] = []
            for await outcome in group { all.append(outcome) }
            return all
        }
        let elapsed = ProcessInfo.processInfo.systemUptime - start
        var failures = 0, busy = 0
        for case .failure(let error) in outcomes {
            failures += 1
            if case OAuthError.temporarilyUnavailable = error { busy += 1 }
        }
        return (failures, busy, elapsed)
    }

    @Test("(b) With the lock held past the timeout, every queued call fails within about one timeout in total")
    func queuedCallsDoNotStack() async throws {
        let path = OAuthStorageBusyTests.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let storage = try OAuthStorage(path: path, busyTimeout: 1.0)
        let rival = try Rival(path: path)
        try rival.run("BEGIN EXCLUSIVE")
        defer { try? rival.run("ROLLBACK") }

        let result = await Self.burst(storage, tag: "stack")

        #expect(result.failures == Self.callers)
        #expect(result.busy == Self.callers, "every failure must be temporarily_unavailable")
        // Stacked, four calls take at least 4 s (each waits the full second). The bound leaves
        // a loaded machine, which the quality gate is, a second of scheduling slack on top of one
        // timeout and still sits below the stacked floor.
        #expect(result.elapsed < 3.0, "took \(result.elapsed) s for \(Self.callers) calls; timeout is 1 s")
        #expect(result.elapsed >= 0.9, "the first call must still wait the timeout")
        // Logical, not clocked: one wait of one timeout in all, however many callers queued.
        let waited = await storage.busyWaitStatistics()
        #expect(waited.seconds <= 1.0, "slept \(waited.seconds) s in total across \(Self.callers) callers")
        #expect(waited.seconds >= 0.5, "the first call must really wait")
    }

    @Test("(a) A lock released after 0.5 s lets every queued call succeed")
    func releasedLockServesEveryone() async throws {
        let path = OAuthStorageBusyTests.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let storage = try OAuthStorage(path: path, busyTimeout: 3.0)
        let rival = try Rival(path: path)
        try rival.run("BEGIN EXCLUSIVE")
        let release = Task {
            try await Task.sleep(nanoseconds: 500_000_000)
            try rival.run("COMMIT")
        }

        let result = await Self.burst(storage, tag: "ok")
        try await release.value

        #expect(result.failures == 0)
        #expect(result.elapsed < 2.5)
        for index in 0..<Self.callers {
            #expect(try await storage.getClient(clientId: "ok-\(index)")?.clientId == "ok-\(index)", "lost write ok-\(index)")
        }
    }

    @Test("(c) After a failed burst the storage recovers, holds no lock, and waits afresh on the next collision")
    func recoversAndLeaksNothing() async throws {
        let path = OAuthStorageBusyTests.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let storage = try OAuthStorage(path: path, busyTimeout: 0.4)
        let rival = try Rival(path: path)
        try rival.run("BEGIN EXCLUSIVE")

        let first = await Self.burst(storage, tag: "first")
        #expect(first.failures == Self.callers)
        try rival.run("ROLLBACK")

        // No leaked lock: the rival can take the write lock, and then give it back.
        try rival.run("BEGIN EXCLUSIVE")
        try rival.run("ROLLBACK")

        // Released: succeeds at once, however recent the failure was.
        let started = ProcessInfo.processInfo.systemUptime
        try await storage.saveClient(OAuthStorageBusyTests.client("after"))
        #expect(ProcessInfo.processInfo.systemUptime - started < 1.0)
        #expect(try await storage.getClient(clientId: "after")?.clientId == "after")
        #expect(try await storage.getClient(clientId: "first-0")?.clientId == nil, "a failed write must not have landed")

        // A later collision is not failed instantly forever: it waits the timeout again.
        try await Task.sleep(nanoseconds: 1_000_000_000)
        try rival.run("BEGIN EXCLUSIVE")
        defer { try? rival.run("ROLLBACK") }
        let before = await storage.busyWaitStatistics()
        await #expect(throws: OAuthError.self) {
            try await storage.saveClient(OAuthStorageBusyTests.client("again"))
        }
        let after = await storage.busyWaitStatistics()
        #expect(after.seconds - before.seconds >= 0.2, "the new collision did not wait afresh")
        #expect(after.seconds - before.seconds <= 0.4)
    }

    @Test("(d) An uncontended workload is not slowed and never fails")
    func uncontendedIsUntouched() async throws {
        let path = OAuthStorageBusyTests.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let storage = try OAuthStorage(path: path)
        for index in 0..<150 {
            try await storage.saveClient(OAuthStorageBusyTests.client("u-\(index)"))
        }
        // No statement met a lock, so none reached the wait budget and none slept.
        let waited = await storage.busyWaitStatistics()
        #expect(waited.statements == 0)
        #expect(waited.seconds == 0)
    }

    @Test("The default busy timeout is 2 s: the measured write windows are milliseconds")
    func defaultIsTwoSeconds() {
        #expect(OAuthStorage.defaultBusyTimeout == 2)
    }
}
