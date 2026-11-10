"""Bounded 16-bit x86 teaching interpreter; never executes native sample code.

Modern Python reconstruction of a 1990s technique, NOT a full DOS/x86 emulator.
Only the six encodings used by the fixed harmless ABC example are supported.
"""
import argparse
import json

CODE = bytes.fromhex('BE1000 B90300 803455 46 E2FA F4')


def run(budget=9, code=CODE, encoded=b'\x14\x17\x16'):
    if not isinstance(budget, int) or isinstance(budget, bool) or not 0 <= budget <= 100000:
        raise ValueError('budget must be an integer in [0, 100000]')
    if len(code) > 16 or len(encoded) != 3:
        raise ValueError('this fixture requires code <= 16 bytes and 3 data bytes')
    memory = bytearray(64)
    memory[:len(code)] = code
    memory[16:19] = encoded
    ip = si = cx = 0
    trace = []

    def read(address):
        if not 0 <= address < len(memory):
            raise IndexError('virtual address out of range')
        return memory[address]

    def word(address):
        return read(address) | (read(address + 1) << 8)

    def result(status):
        return {'status': status, 'data': bytes(memory[16:19]).hex(), 'trace': trace}

    for step in range(1, budget + 1):
        old_ip = ip
        try:
            op = read(ip)
            if op == 0xBE:                      # MOV SI, imm16
                si, ip = word(ip + 1), ip + 3
            elif op == 0xB9:                    # MOV CX, imm16
                cx, ip = word(ip + 1), ip + 3
            elif op == 0x80 and read(ip + 1) == 0x34:  # XOR byte [SI], imm8
                memory[si] = read(si) ^ read(ip + 2)
                ip += 3
            elif op == 0x46:                    # INC SI
                si, ip = (si + 1) & 0xFFFF, ip + 1
            elif op == 0xE2:                    # LOOP rel8 (uses CX, not flags)
                displacement = read(ip + 1)
                if displacement >= 128:
                    displacement -= 256
                cx, ip = (cx - 1) & 0xFFFF, ip + 2
                if cx:
                    ip = (ip + displacement) & 0xFFFF
            elif op == 0xF4:
                return result('HALTED_NO_MATCH')
            else:
                return result('UNSUPPORTED')
        except IndexError:
            return result('OUT_OF_BOUNDS')
        trace.append({'step': step, 'executed_ip': old_ip, 'ip': ip,
                      'si': si, 'cx': cx, 'data': bytes(memory[16:19]).hex()})
        if memory[16:19] == b'ABC':
            return result('MATCH')
    return result('BUDGET_EXHAUSTED')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--budget', type=int, default=9)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.budget), indent=2))
    except ValueError as error:
        parser.error(str(error))
