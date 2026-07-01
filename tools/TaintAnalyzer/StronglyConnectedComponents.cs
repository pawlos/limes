using Mono.Cecil;

namespace TaintAnalyzer;

// Iterative Tarjan strongly-connected-components over a MethodCallGraph. Iterative (explicit
// work stack) rather than recursive so a deep call graph can't overflow our own stack while
// we hunt for stack-overflow bugs. Node visitation follows graph.Nodes order (FullName-sorted),
// so the returned SCC list is deterministic.
public static class StronglyConnectedComponents
{
    public static List<List<MethodDefinition>> Find(MethodCallGraph graph)
    {
        var adj = graph.Adjacency;
        var index = new Dictionary<MethodDefinition, int>();
        var low = new Dictionary<MethodDefinition, int>();
        var onStack = new HashSet<MethodDefinition>();
        var tarjanStack = new Stack<MethodDefinition>();
        int nextIndex = 0;
        var sccs = new List<List<MethodDefinition>>();

        foreach (var start in graph.Nodes)
        {
            if (index.ContainsKey(start)) continue;

            var work = new Stack<(MethodDefinition node, int child)>();
            work.Push((start, 0));

            while (work.Count > 0)
            {
                var (v, child) = work.Pop();

                if (child == 0)
                {
                    index[v] = nextIndex;
                    low[v] = nextIndex;
                    nextIndex++;
                    tarjanStack.Push(v);
                    onStack.Add(v);
                }

                var children = adj.TryGetValue(v, out var cs) ? cs : (IReadOnlyList<MethodDefinition>)Array.Empty<MethodDefinition>();

                if (child < children.Count)
                {
                    // Re-push v to resume at the next child after descending into this one.
                    work.Push((v, child + 1));
                    var w = children[child];
                    if (!index.ContainsKey(w))
                        work.Push((w, 0));
                    else if (onStack.Contains(w))
                        low[v] = Math.Min(low[v], index[w]);
                }
                else
                {
                    // All children processed: v is done. Fold its low-link into its parent.
                    if (low[v] == index[v])
                    {
                        var scc = new List<MethodDefinition>();
                        MethodDefinition w;
                        do
                        {
                            w = tarjanStack.Pop();
                            onStack.Remove(w);
                            scc.Add(w);
                        } while (!ReferenceEquals(w, v));
                        sccs.Add(scc);
                    }

                    if (work.Count > 0)
                    {
                        var parent = work.Peek().node;
                        low[parent] = Math.Min(low[parent], low[v]);
                    }
                }
            }
        }

        return sccs;
    }
}
