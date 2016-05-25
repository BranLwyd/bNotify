package cc.bran.bnotify;

import com.google.common.collect.ImmutableList;
import com.google.common.primitives.UnsignedLongs;

import static com.google.common.base.Preconditions.checkState;

import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;

import cc.bran.bnotify.proto.BNotifyProtos;

/**
 * Tracks used sequence numbers.
 */
public class UsedSequences {

    private static class Range implements Comparable<Range> {

        // Both inclusive.
        private final long min;
        private final long max;

        private Range(long value) {
            this.min = value;
            this.max = value;
        }

        private Range(long min, long max) {
            checkState(UnsignedLongs.compare(min, max) <= 0);
            this.min = min;
            this.max = max;
        }

        @Override
        public int compareTo(Range that) {
            return UnsignedLongs.compare(this.min, that.min);
        }
    }

    private final TreeSet<Range> usedSeqs;

    public static UsedSequences createEmpty() {
        return new UsedSequences(new TreeSet<Range>());
    }

    public static UsedSequences fromProto(List<BNotifyProtos.SequenceRange> seqRanges) {
        TreeSet<Range> usedSeqs = new TreeSet<>();
        Range last = null;
        for (BNotifyProtos.SequenceRange seqRange : seqRanges) {
            Range cur = new Range(seqRange.getMin(), seqRange.getMax());
            checkState(last == null || UnsignedLongs.compare(last.max + 1, cur.min) < 0);
            usedSeqs.add(cur);
            last = cur;
        }
        return new UsedSequences(usedSeqs);
    }

    private UsedSequences(TreeSet<Range> usedSeqs) {
        this.usedSeqs = usedSeqs;
    }

    public List<BNotifyProtos.SequenceRange> toProto() {
        ImmutableList.Builder<BNotifyProtos.SequenceRange> seqRangesBuilder
                = ImmutableList.builder();
        List<BNotifyProtos.SequenceRange> seqRanges = new ArrayList<>();
        for (Range range : usedSeqs) {
            seqRanges.add(BNotifyProtos.SequenceRange.newBuilder()
                    .setMin(range.min)
                    .setMax(range.max)
                    .build());
        }
        return seqRangesBuilder.build();
    }

    /**
     * Tries to use a value.
     * @return true if the value could be used (i.e. has not already been used)
     */
    public boolean use(long value) {
        Range range = new Range(value, value);
        long min = value;
        long max = value;

        Range floor = usedSeqs.floor(range);
        if (floor != null) {
            if (floor.max >= value) {
                return false;
            }
            if (floor.max + 1 == value) {
                min = floor.min;
                // It's safe to remove this early because, given that value is just outside the
                // border of the floor range, it must not be included in the ceiling range since
                // otherwise the ceiling range would already be merged with the floor range. That
                // is, we are going to return true, so it's safe to start removing things
                // willy-nilly.
                usedSeqs.remove(floor);
            }
        }

        Range ceiling = usedSeqs.ceiling(range);
        if (ceiling != null) {
            if (ceiling.min <= value) {
                return false;
            }
            if (ceiling.min - 1 == value) {
                max = ceiling.max;
                usedSeqs.remove(ceiling);
            }
        }

        if (min != value || max != value) {
            range = new Range(min, max);
        }
        usedSeqs.add(range);
        return true;
    }
}
