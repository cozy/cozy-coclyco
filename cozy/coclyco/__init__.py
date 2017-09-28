import argparse
import sys

from .pki import PKI


def cli():
    pki = PKI()

    cli = argparse.ArgumentParser()
    cmds = cli.add_subparsers()

    create = cmds.add_parser("create")
    create.set_defaults(cmd=pki.create_instance)
    create.add_argument("fqdn", help="Instance fqdn")
    create.add_argument("email", help="Email address")

    vhost = cmds.add_parser("vhost")
    vhost.set_defaults(cmd=pki.vhost)
    vhost.add_argument("fqdn", help="Instance fqdn")

    regenerate = cmds.add_parser("regenerate")
    regenerate.set_defaults(cmd=pki.regenerate)
    regenerate.add_argument("fqdn", help="Instance fqdn")

    renew = cmds.add_parser("renew")
    renew.set_defaults(cmd=pki.renew)
    renew.add_argument("fqdn", help="Instance fqdn", nargs="*")

    if len(sys.argv) < 2:
        sys.argv.append("--help")
    args = cli.parse_args()
    args.cmd(args)
