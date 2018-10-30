#!/usr/bin/python
import sys
import time
import math
import signal
import struct
import resource
import ctypes as ct
import multiprocessing

from bcc import BPF
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from distorm3 import Decode, Decode64Bits

bpf_text = '''
#include <linux/ptrace.h>
#include <linux/sched.h>        /* For TASK_COMM_LEN */

#define GTD_DIR_READ            1
#define GTD_DIR_WRITE           2

#define GTD_MAX_PACKET_SIZE     __GTD_MAX_PACKET_SIZE__

struct packet {
    u64 connid;
    u32 pid;
    u32 len;
    u32 direction;
    char comm[TASK_COMM_LEN];
    char data[GTD_MAX_PACKET_SIZE];
};

// use regular array instead percpu array because
// percpu array element size cannot be larger than 3k
BPF_ARRAY(packet_array, struct packet, __NUM_CPUS__);
BPF_PERF_OUTPUT(events);

int probe_TLS_write(struct pt_regs *ctx)
{
    int n, r;
    void **sp, *data;
    struct packet *packet;

    n = bpf_get_smp_processor_id();
    packet = packet_array.lookup(&n);
    if (packet == NULL)
        return 0;

    packet->pid = bpf_get_current_pid_tgid() >> 32;
    packet->direction = GTD_DIR_WRITE;
    bpf_get_current_comm(&packet->comm, sizeof(packet->comm));

    sp = (void **)PT_REGS_SP(ctx);
    packet->connid = (u64)sp[1];
    data = sp[2];
    n = (int)sp[3];

    if (n == 0)
        return 0;

    packet->len = n;
    bpf_probe_read(
        &packet->data,
        // check size in args to make compiler/validator happy
        n > sizeof(packet->data) ? sizeof(packet->data) : n,
        data);

    n += offsetof(struct packet, data);
    r = events.perf_submit(
        ctx,
        packet,
        // check size in args to make compiler/validator happy
        n > sizeof(*packet) ? sizeof(*packet) : n);
    bpf_trace_printk("n = %d r = %d\\n", n, r);

    return 0;
}

int probe_TLS_read_ret(struct pt_regs *ctx)
{
    int n;
    void **sp, *data;
    struct packet *packet;

    n = bpf_get_smp_processor_id();
    packet = packet_array.lookup(&n);
    if (packet == NULL)
        return 0;

    packet->pid = bpf_get_current_pid_tgid() >> 32;
    packet->direction = GTD_DIR_READ;
    bpf_get_current_comm(&packet->comm, sizeof(packet->comm));

    sp = (void **)PT_REGS_SP(ctx);
    packet->connid = (u64)sp[1];
    data = sp[2];
    n = (int)sp[5];

    if (n == 0)
        return 0;

    packet->len = n;
    bpf_probe_read(
        &packet->data,
        // check size in args to make compiler/validator happy
        n > sizeof(packet->data) ? sizeof(packet->data) : n,
        data);

    n += offsetof(struct packet, data);
    events.perf_submit(
        ctx,
        packet,
        // check size in args to make compiler/validator happy
        n > sizeof(*packet) ? sizeof(*packet) : n);

    return 0;
}
'''

def render_bpf_text(text, packet_size):
    replaces = {
        '__GTD_MAX_PACKET_SIZE__': packet_size,
        '__NUM_CPUS__': multiprocessing.cpu_count(),
    }
    for k, v in replaces.items():
        text = text.replace(k, str(v))
    return text

def get_func_insts(prog, func):
    f = open(prog, 'rb')
    e = ELFFile(f)

    sym = None
    for sec in e.iter_sections():
        if sec.name == '.symtab':
            syms = sec.get_symbol_by_name(func)
            if syms is not None:
                sym = syms[0]

    if sym is None:
        raise ValueError('Cannot find function %s:%s' % (file, func))

    sec_idx = sym['st_shndx']
    sym_size = sym['st_size']
    sym_value = sym['st_value']

    sec = e.get_section(sec_idx)
    if sec.name != '.text':
        raise ValueError('Symbol section is not .text')

    sec_offset = sec['sh_offset']
    sec_size = sec['sh_size']
    sec_addr = sec['sh_addr']

    if sym_value < sec_addr or sym_value + sym_size > sec_addr + sec_size:
        raise ValueError('Symbol not in section')

    file_offset = sym_value - sec_addr + sec_offset
    f.seek(file_offset)
    return sym_value, f.read(sym_size)

def get_ret_addrs(func_addr, func_insts):
    addrs = []
    insts = Decode(func_addr, func_insts, type=Decode64Bits)
    for addr, _, asm, _ in insts:
        if asm == 'RET':
            addrs.append(addr)
    return addrs

TASK_COMM_LEN = 16

GTD_DIR_READ = 1
GTD_DIR_WRITE = 2

GTD_MAX_PACKET_SIZE = 1024 * 1024
GTD_BUFFER_SCALE = 10

PCAP_LINK_TYPE = 147    # USER_0

class Packet(ct.Structure):
    _pack_ = 1
    _fields_ = [
        ('connid', ct.c_ulong),
        ('pid', ct.c_uint),
        ('len', ct.c_uint),
        ('direction', ct.c_uint),
        ('comm', ct.c_char * TASK_COMM_LEN),
        # variable length data
    ]

PACKET_SIZE = ct.sizeof(Packet)

packet_count = 0

def parse_event(event, size):
    global packet_count

    packet_count += 1

    packet = ct.cast(event, ct.POINTER(Packet)).contents
    event += PACKET_SIZE

    size -= PACKET_SIZE
    data_len = packet.len
    if  data_len > size:
        data_len = size

    data_type = ct.c_char * data_len
    data = ct.cast(event, ct.POINTER(data_type)).contents

    return packet, data

def print_header(packet, data):
    direction = '>>>'
    if packet.direction == GTD_DIR_READ:
        direction = '<<<'

    ts = time.time()
    ts = time.strftime('%H:%M:%S', time.localtime(ts)) + '.%d' % (ts%1 * 1000)

    print('%s %s process %s[%d] connection %016x len %d(%d)' % (
        ts, direction, packet.comm.decode(), packet.pid,
        packet.connid, len(data), packet.len))

def string_output(cpu, event, size):
    packet, data = parse_event(event, size)
    print_header(packet, data)
    print(str(data.raw, encoding='ascii', errors='ignore'), end='', flush=True)

def ascii(c):
    if c < 32 or c > 126:
        return '.'
    return chr(c)

def hex_print(data):
    for i in range(0, len(data), 16):
        line = '%04x  ' % i
        line += ' '.join('%02x' % x for x in data[i:i+8])
        line += '   ' * (8 - len(data[i:i+8]))
        line += '  '
        line += ' '.join('%02x' % x for x in data[i+8:i+16])
        line += '   ' * (8 - len(data[i+8:i+16]))
        line += '  '
        line += ''.join(ascii(x) for x in data[i:i+16])
        print(line)

def hex_output(cpu, event, size):
    packet, data = parse_event(event, size)
    print_header(packet, data)
    hex_print(data)

def pcap_write_header(snaplen, network):
    header = struct.pack('=IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, snaplen, network)
    sys.stdout.write(header)

def pcap_write_record(ts_sec, ts_usec, orig_len, data):
    header = struct.pack('=IIII', ts_sec, ts_usec, len(data), orig_len)
    sys.stdout.write(header)
    sys.stdout.write(data)

def pcap_output(cpu, event, size):
    packet, data = parse_event(event, size)

    ts = time.time()
    ts_sec = int(ts)
    ts_usec = int((ts % 1) * 10**6)

    if packet.direction == GTD_DIR_READ:
        src, dst = packet.connid, packet.pid
    else:
        src, dst = packet.pid, packet.connid
    header = struct.pack('>QQ', dst, src)

    data = header + data
    size = len(header) + packet.len
    pcap_write_record(ts_sec, ts_usec, size, data)

outputs = {
    'hex': hex_output,
    'string': string_output,
    'pcap': pcap_output,
}

def sig_handler(signum, stack):
    print('\n%d packets captured' % packet_count, file=sys.stderr)
    sys.exit(signum)

def main(args):
    text = render_bpf_text(bpf_text, args.packet_size)
    if args.bpf:
        print(text)
        return

    if args.prog is None:
        if args.pid == -1:
            print('\nMissing pid or prog', file=sys.stderr)
            return
        args.prog = '/proc/%d/exe' % args.pid

    b = BPF(text=text)
    b.attach_uprobe(
        name=args.prog, sym='crypto/tls.(*Conn).Write',
        fn_name='probe_TLS_write', pid=args.pid)

    addr, insts = get_func_insts(args.prog, 'crypto/tls.(*Conn).Read')
    for addr in get_ret_addrs(addr, insts):
        b.attach_uprobe(
            name=args.prog, addr=addr,
            fn_name='probe_TLS_read_ret', pid=args.pid)

    npages = args.packet_size * args.buffer_scale / resource.getpagesize()
    npages = 2 ** math.ceil(math.log(npages, 2))

    output_fn = outputs[args.format]
    b['events'].open_perf_buffer(output_fn, page_cnt=npages)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    if args.format == 'pcap':
        sys.stdout = open(args.output, 'wb')
        pcap_write_header(args.packet_size, PCAP_LINK_TYPE)
    else:
        sys.stdout = open(args.output, 'w')

    while 1:
        b.perf_buffer_poll()

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description='Dump tls traffic of go programs')
    parser.add_argument(
        '--packet-size', type=int, default=GTD_MAX_PACKET_SIZE,
        help='max size of read/write packets')
    parser.add_argument(
        '--buffer-scale', type=int, default=GTD_BUFFER_SCALE,
        help='packet buffer size divided by packet size')
    parser.add_argument(
        '--format', choices=outputs.keys(), default='hex',
        help='output format')
    parser.add_argument(
        '--output', default='/dev/stdout',
        help='output file')
    parser.add_argument(
        '--pid', type=int, default=-1,
        help='sniff this PID only')
    parser.add_argument(
        '--bpf', action='store_true',
        help=argparse.SUPPRESS)
    parser.add_argument(
        '--prog',
        help='go program path')
    args = parser.parse_args()
    main(args)
