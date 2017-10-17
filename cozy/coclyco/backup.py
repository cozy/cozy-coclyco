import json
import os
import os.path
import re
import shutil
import tarfile
import tempfile

import couchdb
import yaml

from .logger import Logger
from .utils import list_safe_get


class Backup:
    def __init__(self):
        config = os.environ.get('COZY_CONFIG', '/etc/cozy/cozy.yml')
        with open(config, 'r') as file:
            config = yaml.load(file)
        self.__url = config['couchdb']['url']
        self.__storage_dir = config['fs']['url'].replace("file://", "")
        self.__server = couchdb.Server(self.__url)

    def __related_dbs(self, fqdn):
        fqdn = fqdn.replace(".", "-")
        regex = re.compile("^%s(/.*)$" % re.escape(fqdn))
        for db in self.__server:
            if regex.match(db):
                yield self.__server[db]

    def __storage(self, fqdn):
        return os.path.join(self.__storage_dir, fqdn)

    def __docs(self, db):
        docs = db.view("_all_docs", include_docs=True)
        Logger.debug("Fetch %i documents", len(docs))
        for doc in docs:
            yield doc.doc

    def __create_db(self, name):
        name = name.replace(".", "-")
        Logger.info("Create CouchDB %s", name)
        db = self.__server.create(name)
        return db

    def __delete_db(self, db):
        Logger.info("Delete CouchDB %s", db.name)
        self.__server.delete(db.name)

    def __dump_to_json(self, db, dir, docs):
        if isinstance(db, str):
            filename = db
        else:
            filename = db.name.split("/")[1]
        filename = "%s.json" % filename
        filename = os.path.join(dir, filename)
        with open(filename, "w") as file:
            json.dump(docs, file)
        return filename

    def __dump_db(self, db, dir):
        Logger.info("Compact CouchDB %s", db.name)
        db.compact()

        Logger.info("Dump CouchDB %s", db.name)

        docs = list(self.__docs(db))
        file = self.__dump_to_json(db, dir, docs)
        return file

    def __restore_db(self, fqdn, db, content):
        db = "%s/%s" % (fqdn, db)
        if db not in self.__server:
            db = self.__create_db(db)
        else:
            db = self.__server[db]

        Logger.debug("Restore %i documents", len(content))
        for doc in content:
            if "_rev" in doc:
                del doc["_rev"]
        results = db.update(content)
        for result in results:
            result, id, rev = result
            if not result:
                Logger.exception("Error occurs on %s : %s", id, rev)

    def __get_global_instance(self, fqdn):
        global_ = self.__server["global/instances"]
        query = {"selector": {"domain": fqdn}, "limit": 1}
        status, msg, instance = global_.resource.post_json("_find", body=query)
        if status != 200:
            Logger.exception("Error occurs : %s %s", status, msg)
        instance = list_safe_get(instance["docs"], 0)
        return global_, instance

    def __delete_global_instance(self, fqdn):
        db, instance = self.__get_global_instance(fqdn)
        if not instance:
            return
        Logger.info("Delete %s %s/%s", db.name, instance["_id"], instance["_rev"])
        db.delete(instance)

    def __dump_global_instance(self, dir, fqdn):
        _, instance = self.__get_global_instance(fqdn)
        if not instance:
            Logger.exception("global/instances document %s not found", fqdn)
        file = self.__dump_to_json("global", dir, [instance])
        return file

    def __dump_couchdb(self, dir, fqdn, tar):
        file = self.__dump_global_instance(dir, fqdn)
        target = os.path.basename(file)
        target = os.path.join("couchdb", target)
        tar.add(file, target)

        for db in self.__related_dbs(fqdn):
            file = self.__dump_db(db, dir)
            target = os.path.basename(file)
            target = os.path.join("couchdb", target)
            tar.add(file, target)

    def __dump_storage(self, fqdn, tar):
        storage = self.__storage(fqdn)
        Logger.info("Backup storage %s", storage)
        tar.add(storage, "storage")

    def __backup(self, fqdn):
        Logger.info("Backup %s", fqdn)
        with tempfile.TemporaryDirectory() as dir:
            filename = "%s.tar.xz" % fqdn
            Logger.info(filename)
            with tarfile.open(filename, "w|xz") as tar:
                self.__dump_couchdb(dir, fqdn, tar)
                self.__dump_storage(fqdn, tar)

    def backup(self, fqdns):
        for fqdn in fqdns:
            self.__backup(fqdn)

    def __delete_storage(self, fqdn):
        storage = self.__storage(fqdn)
        Logger.info("Delete storage %s", storage)
        if os.path.isdir(storage):
            shutil.rmtree(storage)

    def __extract_members(self, tar, prefix):
        offset = len(prefix)
        for member in tar.getmembers():
            if member.name.startswith(prefix):
                member.name = member.name[offset:]
                yield member

    def __extract_couchdb_members(self, tar):
        yield from self.__extract_members(tar, "couchdb/")

    def __restore_couchdb(self, fqdn, tar):
        for db in self.__related_dbs(fqdn):
            self.__delete_db(db)

        members = self.__extract_couchdb_members(tar)
        for member in members:
            db = member.name
            content = tar.extractfile(member)
            content = content.read().decode()
            content = json.loads(content)

            if db == "global.json":
                self.__delete_global_instance(fqdn)
                self.__restore_db("global", "instances", content)
            else:
                self.__restore_db(fqdn, db, content)

    def __extract_storage_members(self, tar):
        yield from self.__extract_members(tar, "storage/")

    def __restore_storage(self, fqdn, tar):
        self.__delete_storage(fqdn)

        storage = self.__storage(fqdn)
        Logger.info("Restore storage %s", storage)
        members = self.__extract_storage_members(tar)
        tar.extractall(storage, members)

    def restore(self, fqdn, archive):
        with tarfile.open(archive, "r") as tar:
            self.__restore_couchdb(fqdn, tar)
            self.__restore_storage(fqdn, tar)
