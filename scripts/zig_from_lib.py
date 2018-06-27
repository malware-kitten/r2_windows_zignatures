import sys
import r2pipe
import argparse
import subprocess
import tempfile
import os
import simplejson as json
import shutil
from pprint import pprint, pformat

def recursive_all_files(directory, ext_filter=None):
    all_files = []
    dir_content = []
    ret = []
    if os.path.isfile(directory):
        dir_content = [directory]
    else:
        if '*' in directory:
            dir_content = glob.glob(directory)
        else:
            try:
                dir_content = os.listdir(directory)
            except Exception as e:
                #print 'Exception listing contents of %s. Skipping' % (directory)
                return []
    for f in dir_content:
        if os.path.isdir(directory):
            rel_path = os.path.join(directory,f)
        else:
            rel_path = f
        if os.path.isfile(rel_path):
            all_files.append(rel_path)
        elif f == '.' or f == '..':
            pass
        else:
            all_files += recursive_all_files(rel_path,ext_filter)

    for f in all_files:
        if (ext_filter is None or os.path.splitext(f)[1] == '.%s' % ext_filter):
            ret.append(f)
    return ret

def generate_zigs_json(f):
    r2p = r2pipe.open(f)
    #analyze and generate zigs
    r2p.cmd('aaa; zg')
    zigs = r2p.cmdj('zj')
    r2p.quit()
    return zigs

def generate_zigs_sdb(f, output):
    r2p = r2pipe.open(f)
    #analyze and generate zigs
    r2p.cmd('aaa; zg')
    zigs = r2p.cmd('zos %s' % output)
    r2p.quit()

def dedup(zignatures):
    observed = {}
    uniq_results = []
    for zig in zignatures:
        if zig['bytes'] in observed:
            print("Removing %s" % zig)
        else:
            observed[zig['bytes']] = 1
            uniq_results.append(zig)
    return uniq_results

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate R2 Zignatures from .lib files')
    parser.add_argument("-f", "--file", required=True, help=".lib file to use")
    parser.add_argument("-o", "--output", required=True, help="output filename")
    parser.add_argument("-s", "--sdb", action='store_true', help="store as sdb files")
    args = parser.parse_args()

    with open(args.file,'rb') as fp:
        contents = fp.read(7)
    if contents == "!<arch>":
        target_path = tempfile.mkdtemp()
        command = ['7z', 'x', '-o'+target_path, args.file]
        output = subprocess.check_output(command)
        results = []
        for f in recursive_all_files(target_path, 'obj'):
            if args.sdb:
                generate_zigs_sdb(f, f.split("\\")[-1]+".sdb")
            else:
                json_items = generate_zigs_json(f)
                for zigs in json_items:
                    results.append(zigs)
    else:
        print("File magic does not match, check to make sure this is a .lib file")

    #cleanup
    shutil.rmtree(target_path)
    if args.sdb:
        #no output needed, file was written in r2
        pass
    else:
        uniq_results = dedup(results)
        if len(uniq_results) > 0:
            with open(args.output, 'w') as fp:
                fp.write(pformat(uniq_results))
