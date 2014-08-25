#!/usr/bin/env python
#
# Archive reported tasks to the NFS mount to save space on analysis machines.

import os.path
import sys
import time
import socket
from optparse import OptionParser
from shutil import move

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.core.database import Database, TASK_REPORTED
from lib.cuckoo.common.colors import bold, green, red, yellow

def _analysis_dir(task_id):
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", 'storage', 'analyses', str(task_id)))

def main():
    """main function for standalone usage"""
    usage = "usage: %prog [options]"
    parser = OptionParser(usage=usage)
    parser.add_option('-a', '--archive-toplevel-dir', default='/mnt/cuckoo_archive',
                      help='Archive top-level directory [default: %default]')
    parser.add_option('-m', '--local-machine-dir', default=socket.gethostname(),
                      help='Machine-specific directory [default: $HOST]')

    (options, args) = parser.parse_args()

    if len(args) != 0:
        parser.print_help()
        return 2

    # do stuff
    archive_dir = os.path.join(options.archive_toplevel_dir, options.local_machine_dir)
    try:
        os.mkdir(archive_dir)
    except OSError: # already exists
        pass

    db = Database()

    for task in db.list_tasks(status=TASK_REPORTED):
        task_path_src = _analysis_dir(task.id)

        if not os.path.islink(task_path_src):
            task_path_dst = os.path.join(archive_dir, str(task.id))
            move(task_path_src, task_path_dst)
            os.symlink(task_path_dst, task_path_src)
            print(bold(green('Successfully')) + ' archived %s' % task_path_dst)

if __name__ == '__main__':
    sys.exit(main())
