using Bastion.Core.Models;
using Bastion.Core.Runtime;

namespace Bastion.Core.Tests;

public class JournalTests
{
    private static SecurityEvent Event(Severity severity, params string[] actions) =>
        new() { Category = EventCategory.Network, Severity = severity, Title = "t", Actions = [.. actions] };

    [Fact]
    public void ClearKeepsOpenThreatsUnlessEverythingIsRequested()
    {
        var dir = TestFiles.TempDir();
        var journal = new EventJournal(dir);
        var openThreat = Event(Severity.High, EventActions.Kill, EventActions.Ignore);
        var resolved = Event(Severity.High, EventActions.Kill);
        var info = Event(Severity.Info);
        foreach (var e in new[] { openThreat, resolved, info })
            journal.Add(e);
        journal.Resolve(resolved, "erledigt");

        Assert.Equal(2, journal.Clear());
        Assert.Equal([openThreat.Id], journal.Recent(10).Select(e => e.Id));

        // The open threat survives a restart because it was written back to disk.
        Assert.Equal([openThreat.Id], new EventJournal(dir).Recent(10).Select(e => e.Id));

        Assert.Equal(1, journal.Clear(includeOpen: true));
        Assert.Empty(journal.Recent(10));
        Assert.Empty(new EventJournal(dir).Recent(10));
    }
}
