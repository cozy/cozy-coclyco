import subprocess
import threading

from .utils import filter_sensible_field
from .logger import Logger


class StreamAndString:
    def __init__(self, stream):
        self.__stream = stream
        self.__string = b""

    def __write(self, line):
        self.__string += line
        self.__stream(line.decode().rstrip())

    def __str__(self):
        return self.__string.decode().strip()

    def process(self, stream):
        for line in stream:
            self.__write(line)


class ImprovedCalledProcessError(subprocess.CalledProcessError):
    def __init__(self, returncode, cmd, stdout=None, stderr=None):
        subprocess.CalledProcessError.__init__(self, returncode=returncode,
                                               cmd=cmd)
        self.__stdout = stdout
        self.__stderr = stderr

    def __str__(self):
        return "Command '%s' returned non-zero exit status %d\nstdout:\n%s\nstderr:\n%s" % \
               (" ".join(self.cmd), self.returncode, self.__stdout.strip(),
                self.__stderr.strip())


class Cmd:
    @staticmethod
    def exec(*cmd, **kwargs):
        level = kwargs.pop("level", "debug")
        Logger.log(level, "[cmd] Execute %s (%s)", " ".join(cmd),
                   filter_sensible_field(kwargs))
        env = kwargs.pop("env", None)

        stdin = kwargs.get("stdin")
        stdout = StreamAndString(Logger.debug)
        stderr = StreamAndString(Logger.error)

        try:
            process = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, env=env)
        except Exception as e:
            Logger.error("Error occurs during command %s", cmd)
            Logger.error(e)
            raise

        threads = [
            threading.Thread(target=stdout.process, args=[process.stdout]),
            threading.Thread(target=stderr.process, args=[process.stderr])]
        if stdin:
            process.stdin.write(stdin)
        [thread.start() for thread in threads]
        retcode = process.wait()
        for thread in threads:
            thread.join()
        stdout, stderr = str(stdout), str(stderr)
        if retcode:
            e = ImprovedCalledProcessError(retcode, cmd, stdout, stderr)
            Logger.error("Error occurs during command %s", cmd)
            Logger.error(stderr)
            raise e
        return [stdout, stderr]

    @staticmethod
    def ssh(host, *cmd):
        cmd = ["ssh", "-o", "ControlMaster=no", host] + list(cmd)
        return Cmd.exec(*cmd)
