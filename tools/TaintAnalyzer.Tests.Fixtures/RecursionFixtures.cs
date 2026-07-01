#nullable disable
using System;
using System.Collections.Generic;

namespace TaintAnalyzer.Tests.Fixtures.Recursion;

// Models the Microsoft.OpenApi circular-$ref shape (GHSA-v5pm-xwqc-g5wc / CVE-2026-49451,
// CWE-674 Uncontrolled Recursion). A reference holder resolves its target by walking the
// reference chain recursively; a circular chain (A -> B -> A) overflows the stack.
public class ReferenceHolder
{
    public ReferenceHolder Next;
    public object Value;

    // Vulnerable: follows the reference chain with no cycle guard -> FLAG (self-recursion).
    public object ResolveTarget()
    {
        if (Next != null)
            return Next.ResolveTarget();
        return Value;
    }
}

public class GuardedReferenceHolder
{
    public GuardedReferenceHolder Next;
    public object Value;

    // Patched (mirrors the 2.7.5 fix): a visited HashSet threads through the recursion and
    // throws on a cycle -> CLEAR.
    public object ResolveTarget(HashSet<GuardedReferenceHolder> visited)
    {
        if (!visited.Add(this))
            throw new InvalidOperationException("circular reference detected");
        if (Next != null)
            return Next.ResolveTarget(visited);
        return Value;
    }
}

public class DepthLimitedHolder
{
    public DepthLimitedHolder Next;
    public object Value;

    // Patched via a recursion depth cap -> CLEAR.
    public object ResolveTarget(int depth)
    {
        if (depth > 100)
            throw new InvalidOperationException("maximum resolution depth exceeded");
        if (Next != null)
            return Next.ResolveTarget(depth + 1);
        return Value;
    }
}

// Faithful to BaseOpenApiReferenceHolder.RecursiveTarget: the recursion lives in a property
// getter. Getters are normally rejected as candidates; the recursion profile relaxes that.
public class OpenApiReferenceHolder
{
    public OpenApiReferenceHolder Reference;
    public object Target;

    // Vulnerable getter -> FLAG.
    public object RecursiveTarget
    {
        get
        {
            if (Reference != null)
                return Reference.RecursiveTarget;
            return Target;
        }
    }
}

public class PlainResolver
{
    // No self-call -> CLEAR (not a recursion candidate).
    public object Resolve(ReferenceHolder h)
    {
        return h != null ? h.Value : null;
    }
}

// Mutual recursion (A -> B -> A): neither method calls itself directly, so only the SCC pass
// flags the cycle. No cycle guard -> FLAG.
public class MutualA
{
    public MutualB Peer;
    public object Value;

    public object Resolve()
    {
        if (Peer != null)
            return Peer.Resolve();
        return Value;
    }
}

public class MutualB
{
    public MutualA Peer;
    public object Value;

    public object Resolve()
    {
        if (Peer != null)
            return Peer.Resolve();
        return Value;
    }
}

// Mutual recursion with a visited HashSet threaded through the cycle -> CLEAR.
public class GuardedMutualA
{
    public GuardedMutualB Peer;
    public object Value;

    public object Resolve(HashSet<object> visited)
    {
        if (!visited.Add(this))
            throw new InvalidOperationException("circular reference detected");
        if (Peer != null)
            return Peer.Resolve(visited);
        return Value;
    }
}

public class GuardedMutualB
{
    public GuardedMutualA Peer;
    public object Value;

    public object Resolve(HashSet<object> visited)
    {
        if (Peer != null)
            return Peer.Resolve(visited);
        return Value;
    }
}
