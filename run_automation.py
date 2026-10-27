import os
import argparse
import logging

def execute_command(cmd: str):
    logging.debug(f'Execute command: {cmd}')
    return os.system(cmd)

def remove_cache_files(binary):
    extensions = ['.id0', '.id1', '.id2', '.nam', '.til', '.asm', '.log']
    for ext in extensions:
        file_path = binary + ext
        if os.access(file_path, os.F_OK):
            os.remove(file_path)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--script', required=True, help='IDA python script')
    parser.add_argument('-b', '--binary', required=True, help='Binary executable program or i64 database')
    args = parser.parse_args()

    logging.basicConfig(format='%(asctime)s : %(levelname)s : %(message)s', level=logging.INFO)

    script = os.path.abspath(args.script)
    binary = os.path.abspath(args.binary)

    if not os.access(script, os.F_OK) or not os.access(binary, os.F_OK):
        logging.error('Script or Binary not found.')
        exit(1)

    if binary.endswith('.i64'):
        remove_cache_files(binary[:-4])
        binary_ida = binary
    else:
        remove_cache_files(binary)
        binary_ida = binary + '.i64'
        if os.access(binary_ida, os.F_OK):
            os.remove(binary_ida)

    if not os.access(binary_ida, os.F_OK):
        logging.info('Generating i64 file')
        execute_command(f'idat64 -B {binary}')
        if os.access(binary + '.asm', os.F_OK):
            os.remove(binary + '.asm')

    binary_log = binary + '.log'
    logging.info(f'Executing {script}')
    execute_command(f'idat64 -A -L{binary_log} -S{script} {binary_ida}')

    try:
        with open(binary_log, 'r') as f:
            content = f.read()
            head = content.find('-----BEGIN OUTPUT-----') + len('-----BEGIN OUTPUT-----')
            tail = content.find('-----END OUTPUT-----')
            print(content[head:tail].strip())
    except FileNotFoundError:
        logging.error("Log file not generated.")