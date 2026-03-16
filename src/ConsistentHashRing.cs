using System.Security.Cryptography;
using System.Text;

namespace Philiprehberger.Hashing;

/// <summary>
/// A thread-safe consistent hash ring for distributing keys across a set of nodes.
/// Uses virtual nodes for better distribution uniformity.
/// </summary>
/// <typeparam name="T">The type of node stored in the ring.</typeparam>
public sealed class ConsistentHashRing<T> where T : notnull
{
    private readonly int _virtualNodes;
    private readonly object _lock = new();
    private readonly SortedDictionary<uint, T> _ring = new();
    private readonly Dictionary<T, List<uint>> _nodeHashes = new();
    private uint[] _sortedKeys = [];

    /// <summary>
    /// Creates a new <see cref="ConsistentHashRing{T}"/> instance.
    /// </summary>
    /// <param name="virtualNodes">
    /// The number of virtual nodes per physical node. Higher values give more uniform
    /// distribution at the cost of memory. Default is 150.
    /// </param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="virtualNodes"/> is less than 1.
    /// </exception>
    public ConsistentHashRing(int virtualNodes = 150)
    {
        if (virtualNodes < 1)
            throw new ArgumentOutOfRangeException(nameof(virtualNodes), virtualNodes, "Virtual nodes must be at least 1.");

        _virtualNodes = virtualNodes;
    }

    /// <summary>
    /// Gets the number of physical nodes in the ring.
    /// </summary>
    public int NodeCount
    {
        get
        {
            lock (_lock)
            {
                return _nodeHashes.Count;
            }
        }
    }

    /// <summary>
    /// Adds a node to the ring. If the node already exists, this is a no-op.
    /// </summary>
    /// <param name="node">The node to add.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="node"/> is <c>null</c>.</exception>
    public void AddNode(T node)
    {
        ArgumentNullException.ThrowIfNull(node);

        lock (_lock)
        {
            if (_nodeHashes.ContainsKey(node))
                return;

            var hashes = new List<uint>(_virtualNodes);
            for (var i = 0; i < _virtualNodes; i++)
            {
                var hash = ComputeHash($"{node}:{i}");
                _ring[hash] = node;
                hashes.Add(hash);
            }

            _nodeHashes[node] = hashes;
            RebuildSortedKeys();
        }
    }

    /// <summary>
    /// Removes a node from the ring. If the node does not exist, this is a no-op.
    /// </summary>
    /// <param name="node">The node to remove.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="node"/> is <c>null</c>.</exception>
    public void RemoveNode(T node)
    {
        ArgumentNullException.ThrowIfNull(node);

        lock (_lock)
        {
            if (!_nodeHashes.TryGetValue(node, out var hashes))
                return;

            foreach (var hash in hashes)
            {
                _ring.Remove(hash);
            }

            _nodeHashes.Remove(node);
            RebuildSortedKeys();
        }
    }

    /// <summary>
    /// Gets the node responsible for the given key.
    /// </summary>
    /// <param name="key">The key to look up.</param>
    /// <returns>The node responsible for this key.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is <c>null</c>.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the ring is empty.</exception>
    public T GetNode(string key)
    {
        ArgumentNullException.ThrowIfNull(key);

        lock (_lock)
        {
            if (_sortedKeys.Length == 0)
                throw new InvalidOperationException("The hash ring is empty. Add at least one node before calling GetNode.");

            var hash = ComputeHash(key);
            var index = FindNextKey(hash);
            return _ring[_sortedKeys[index]];
        }
    }

    private int FindNextKey(uint hash)
    {
        var lo = 0;
        var hi = _sortedKeys.Length - 1;

        if (hash > _sortedKeys[hi])
            return 0; // wrap around

        while (lo < hi)
        {
            var mid = lo + (hi - lo) / 2;
            if (_sortedKeys[mid] < hash)
                lo = mid + 1;
            else
                hi = mid;
        }

        return lo;
    }

    private void RebuildSortedKeys()
    {
        _sortedKeys = [.. _ring.Keys];
    }

    private static uint ComputeHash(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return BitConverter.ToUInt32(bytes, 0);
    }
}
