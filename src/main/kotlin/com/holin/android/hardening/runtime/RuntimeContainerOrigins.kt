package com.holin.android.hardening.runtime

import org.objectweb.asm.tree.AbstractInsnNode
import java.util.IdentityHashMap

/** Exact immutable identities, with sparse storage independent of the largest identity. */
internal class RuntimeContainerOrigins {
    private val instructions = arrayListOf<AbstractInsnNode>()
    private val singletons = IdentityHashMap<AbstractInsnNode, Snapshot>()
    private var populated = LongArray(0)
    // Fixed-point passes repeat small sparse merges. Bound retention to 64 pairs of
    // at most 256 identities; never retain the unbounded history of large summaries.
    private val sparseMergeLeft = arrayOfNulls<Snapshot>(64)
    private val sparseMergeRight = arrayOfNulls<Snapshot>(64)
    private val sparseMergeResults = arrayOfNulls<Snapshot>(64)
    val empty = Snapshot(this, -1, null, null, 0, 0)

    fun single(instruction: AbstractInsnNode): Snapshot = singletons.getOrPut(instruction) {
        val id = instructions.size
        instructions += instruction
        Snapshot(this, id, null, null, 0, 1)
    }

    fun markPopulated(instruction: AbstractInsnNode) {
        val id = requireNotNull(singletons[instruction]).first()
        val word = id ushr 6
        if (word >= populated.size) populated = populated.copyOf(maxOf(word + 1, populated.size * 2, 4))
        populated[word] = populated[word] or (1L shl (id and 63))
    }

    fun forEachPopulated(source: Snapshot, action: (AbstractInsnNode) -> Unit) {
        require(source.owner === this) { "Container origins belong to a different analysis" }
        source.forEachIntersection(populated) { action(instructions[it]) }
    }

    fun union(sources: Iterable<Snapshot?>): Snapshot {
        var first: Snapshot? = null
        var second: Snapshot? = null
        var multiple: MutableList<Snapshot>? = null
        sources.forEach { source ->
            if (source == null) return@forEach
            require(source.owner === this) { "Container origins belong to a different analysis" }
            if (source.isEmpty()) return@forEach
            when {
                first == null -> first = source
                second == null -> second = source
                else -> {
                    val values = multiple ?: arrayListOf(requireNotNull(first), requireNotNull(second)).also { multiple = it }
                    values += source
                }
            }
        }
        val values = multiple ?: return union(first, second)
        val largest = values.maxBy { it.size }
        if (values.all { it === largest || largest.includes(it) }) return largest
        val low = values.minOf { it.first() }
        val high = values.maxOf { it.last() }
        val offset = low ushr 6
        val wordCount = (high ushr 6) - offset + 1
        val upper = values.sumOf { it.size.toLong() }
        if (wordCount.toLong() * 8 <= upper * 4) {
            val words = LongArray(wordCount)
            values.forEach { it.addTo(words, offset) }
            val count = words.sumOf(java.lang.Long::bitCount)
            if (wordCount.toLong() * 8 <= count.toLong() * 4) return Snapshot(this, -1, null, words, offset, count)
            val ids = IntArray(count)
            var position = 0
            words.forEachIndexed { index, value ->
                var word = value
                while (word != 0L) {
                    ids[position++] = ((index + offset) shl 6) + java.lang.Long.numberOfTrailingZeros(word)
                    word = word and (word - 1)
                }
            }
            return Snapshot(this, -1, ids, null, 0, count)
        }
        val ids = IntArray(upper.toInt())
        var position = 0
        values.forEach { value ->
            position = value.appendIds(ids, position)
        }
        ids.sort()
        var count = 0
        ids.forEach { id -> if (count == 0 || ids[count - 1] != id) ids[count++] = id }
        return Snapshot(this, -1, ids.copyOf(count), null, 0, count)
    }

    fun union(first: Snapshot?, second: Snapshot?): Snapshot {
        require(first == null || first.owner === this) { "Container origins belong to a different analysis" }
        require(second == null || second.owner === this) { "Container origins belong to a different analysis" }
        if (first == null || first.isEmpty()) return second ?: empty
        if (second == null || second.isEmpty() || first === second) return first
        if (first.size >= second.size && first.includes(second)) return first
        if (second.size >= first.size && second.includes(first)) return second
        val low = minOf(first.first(), second.first())
        val high = maxOf(first.last(), second.last())
        val offset = low ushr 6
        val wordCount = (high ushr 6) - offset + 1
        if (wordCount.toLong() * 8 <= (first.size.toLong() + second.size) * 4) {
            val words = LongArray(wordCount)
            first.addTo(words, offset)
            second.addTo(words, offset)
            val count = words.sumOf(java.lang.Long::bitCount)
            if (words.size.toLong() * 8 <= count.toLong() * 4) return Snapshot(this, -1, null, words, offset, count)
            val ids = IntArray(count)
            var position = 0
            words.forEachIndexed { index, value ->
                var remaining = value
                while (remaining != 0L) {
                    ids[position++] = ((index + offset) shl 6) + java.lang.Long.numberOfTrailingZeros(remaining)
                    remaining = remaining and (remaining - 1)
                }
            }
            return Snapshot(this, -1, ids, null, 0, count)
        }
        val cacheable = first.size + second.size in 16..256
        val cacheIndex = if (cacheable) (System.identityHashCode(first) xor System.identityHashCode(second)) and 63 else -1
        if (cacheIndex >= 0 && ((sparseMergeLeft[cacheIndex] === first && sparseMergeRight[cacheIndex] === second) ||
            (sparseMergeLeft[cacheIndex] === second && sparseMergeRight[cacheIndex] === first))) {
            return requireNotNull(sparseMergeResults[cacheIndex])
        }
        first.mergeSparse(second)?.let {
            if (cacheIndex >= 0) {
                sparseMergeLeft[cacheIndex] = first
                sparseMergeRight[cacheIndex] = second
                sparseMergeResults[cacheIndex] = it
            }
            return it
        }
        val ids = IntArray(first.size + second.size)
        var a = first.nextId(0)
        var b = second.nextId(0)
        var count = 0
        while (a >= 0 || b >= 0) {
            val id = if (b < 0 || a >= 0 && a < b) a else b
            ids[count++] = id
            if (a == id) a = first.nextId(a + 1)
            if (b == id) b = second.nextId(b + 1)
        }
        return Snapshot(this, -1, ids.copyOf(count), null, 0, count)
    }

    internal class Snapshot internal constructor(
        internal val owner: RuntimeContainerOrigins,
        private val only: Int,
        private val sparse: IntArray?,
        private val words: LongArray?,
        private val offset: Int,
        override val size: Int,
    ) : AbstractSet<AbstractInsnNode>() {
        internal fun mergeSparse(other: Snapshot): Snapshot? {
            if (words != null || other.words != null) return null
            val ids = IntArray(size + other.size)
            val a = sparse
            val b = other.sparse
            if (a != null && b != null) {
                var left = 0
                var right = 0
                var count = 0
                while (left < a.size && right < b.size) {
                    val x = a[left]
                    val y = b[right]
                    if (x <= y) {
                        ids[count++] = x
                        left++
                        if (x == y) right++
                    } else {
                        ids[count++] = y
                        right++
                    }
                }
                val remaining = if (left < a.size) a else b
                val position = if (left < a.size) left else right
                val length = remaining.size - position
                System.arraycopy(remaining, position, ids, count, length)
                count += length
                return Snapshot(owner, -1, if (count == ids.size) ids else ids.copyOf(count), null, 0, count)
            }
            var left = 0
            var right = 0
            var count = 0
            while (left < size && right < other.size) {
                val x = a?.get(left) ?: only
                val y = b?.get(right) ?: other.only
                if (x < y) { ids[count++] = x; left++ }
                else if (y < x) { ids[count++] = y; right++ }
                else { ids[count++] = x; left++; right++ }
            }
            while (left < size) {
                ids[count++] = a?.get(left) ?: only
                left++
            }
            while (right < other.size) {
                ids[count++] = b?.get(right) ?: other.only
                right++
            }
            return Snapshot(owner, -1, if (count == ids.size) ids else ids.copyOf(count), null, 0, count)
        }

        internal fun first(): Int = when {
            only >= 0 -> only
            sparse != null -> sparse[0]
            words != null -> (offset shl 6) + java.lang.Long.numberOfTrailingZeros(words[0])
            else -> -1
        }

        internal fun last(): Int = when {
            only >= 0 -> only
            sparse != null -> sparse.last()
            words != null -> ((offset + words.lastIndex) shl 6) + 63 - java.lang.Long.numberOfLeadingZeros(words.last())
            else -> -1
        }

        private fun containsId(id: Int): Boolean {
            if (only >= 0) return id == only
            if (sparse != null) return sparse.binarySearch(id) >= 0
            if (words == null) return false
            val word = (id ushr 6) - offset
            return word in words.indices && words[word] and (1L shl (id and 63)) != 0L
        }

        internal fun nextId(from: Int): Int {
            if (only >= 0) return if (only >= from) only else -1
            if (sparse != null) {
                val found = sparse.binarySearch(from)
                val index = if (found < 0) -found - 1 else found
                return if (index < sparse.size) sparse[index] else -1
            }
            if (words == null) return -1
            var index = maxOf(0, (from ushr 6) - offset)
            if (index >= words.size) return -1
            var word = words[index]
            if ((from ushr 6) >= offset) word = word and (-1L shl (from and 63))
            while (word == 0L) {
                if (++index >= words.size) return -1
                word = words[index]
            }
            return ((index + offset) shl 6) + java.lang.Long.numberOfTrailingZeros(word)
        }

        internal fun includes(other: Snapshot): Boolean {
            if (sparse != null && other.sparse != null && other.size.toLong() * 4 >= size) {
                var position = 0
                other.sparse.forEach { id ->
                    while (position < sparse.size && sparse[position] < id) position++
                    if (position == sparse.size || sparse[position] != id) return false
                }
                return true
            }
            val otherWords = other.words
            if (words != null && otherWords != null) {
                otherWords.forEachIndexed { index, word ->
                    val target = index + other.offset - offset
                    if (target !in words.indices || word and words[target].inv() != 0L) return false
                }
                return true
            }
            var id = other.nextId(0)
            while (id >= 0) {
                if (!containsId(id)) return false
                id = other.nextId(id + 1)
            }
            return true
        }

        internal fun appendIds(target: IntArray, start: Int): Int {
            if (sparse != null) {
                System.arraycopy(sparse, 0, target, start, sparse.size)
                return start + sparse.size
            }
            var position = start
            if (only >= 0) target[position++] = only
            else words?.forEachIndexed { index, value ->
                var word = value
                while (word != 0L) {
                    target[position++] = ((index + offset) shl 6) + java.lang.Long.numberOfTrailingZeros(word)
                    word = word and (word - 1)
                }
            }
            return position
        }

        internal fun addTo(target: LongArray, targetOffset: Int) {
            if (words != null) words.forEachIndexed { index, word ->
                val destination = index + offset - targetOffset
                target[destination] = target[destination] or word
            } else if (sparse != null) sparse.forEach { id ->
                val destination = (id ushr 6) - targetOffset
                target[destination] = target[destination] or (1L shl (id and 63))
            } else if (only >= 0) {
                val destination = (only ushr 6) - targetOffset
                target[destination] = target[destination] or (1L shl (only and 63))
            }
        }

        internal fun forEachIntersection(populated: LongArray, action: (Int) -> Unit) {
            if (words != null) {
                val limit = minOf(words.size, populated.size - offset)
                for (index in 0 until limit) {
                    var word = words[index] and populated[index + offset]
                    while (word != 0L) {
                        action(((index + offset) shl 6) + java.lang.Long.numberOfTrailingZeros(word))
                        word = word and (word - 1)
                    }
                }
            } else if (sparse != null) sparse.forEach { id ->
                val index = id ushr 6
                if (index < populated.size && populated[index] and (1L shl (id and 63)) != 0L) action(id)
            } else if (only >= 0 && (only ushr 6) < populated.size && populated[only ushr 6] and (1L shl (only and 63)) != 0L) action(only)
        }

        override fun contains(element: AbstractInsnNode): Boolean {
            val id = owner.singletons[element]?.only ?: return false
            return containsId(id)
        }

        override fun iterator(): Iterator<AbstractInsnNode> = object : Iterator<AbstractInsnNode> {
            private var position = 0
            private var id = if (sparse == null) nextId(0) else -1
            override fun hasNext(): Boolean = if (sparse != null) position < sparse.size else id >= 0
            override fun next(): AbstractInsnNode {
                if (!hasNext()) throw NoSuchElementException()
                val current = if (sparse != null) sparse[position++] else id.also { id = nextId(it + 1) }
                return owner.instructions[current]
            }
        }
    }
}
