# -*- coding: utf-8 -*-
"""VeiL asyncio linux authentication utils."""

import asyncio
import shlex
import stat
from pathlib import Path
from typing import List, Optional

try:
    import pam
except ImportError:  # pragma: no cover
    pam = None


class CommandType:
    """Descriptor for command type checking.

    Command path must be a executable file.
    """

    @staticmethod
    def user_executable(filepath: Path) -> bool:
        """File can be executed by user (owner)."""
        st = filepath.stat()
        return bool(st.st_mode & stat.S_IXUSR)

    @staticmethod
    def user_readable(filepath: Path) -> bool:
        """File can be read by user (owner)."""
        st = filepath.stat()
        return bool(st.st_mode & stat.S_IRUSR)

    def __init__(self, name):
        """Set attribute name and checking value type."""
        self.name = name
        self.value_type = str

    def __set__(self, instance, value):
        """Check that attribute value type equals value_type."""
        if not isinstance(value, self.value_type):
            raise TypeError('{val} is not a {val_type}'.format(val=value, val_type=self.value_type))  # noqa: E501
        value = Path(value)
        if not value.is_file():
            raise FileExistsError('{file_path} is not a file.'.format(file_path=value))
        if not self.user_executable(value):
            raise PermissionError('{file_path} can`t be executed by user.'.format(file_path=value))  # noqa: E501
        instance.__dict__[self.name] = str(value)

    def __get__(self, instance, class_) -> str:
        """Return attribute value."""
        return instance.__dict__[self.name]


class OptionalCommandType(CommandType):
    """Descriptor for nullable shell command."""

    def __set__(self, instance, value):
        """Check that attribute value type equals value_type or None."""
        if not value:
            instance.__dict__[self.name] = None
        else:
            super().__set__(instance=instance, value=value)


class VeilResult:
    """VeilAuthPam operation result.

    Attributes:
        return_code: all instead of 0 is an error.
        error_msg: stderr value.
        stdout_msg: stdout value.
    """

    def __init__(self, return_code: int, error_msg: str, stdout_msg: str):
        """Please see help(VeilResult) for more info."""
        self.return_code = return_code
        self.error_msg = error_msg
        self.stdout_msg = stdout_msg

    @property
    def success(self):
        """If no information about errors - operation result is success."""
        return bool(self.return_code == 0 and not self.error_msg)

    def __str__(self):
        """Object print prettify."""
        if self.success:
            return 'return code: {}, msg: {}'.format(self.return_code, self.stdout_msg)
        else:
            return 'return code: {}, msg: {}'.format(self.return_code, self.error_msg)


class VeilAuthPam:
    """VeilClient class.

    Private attributes:
        __USER_ADD_CMD: str with validated Path to executable command.
        __GROUP_ADD_CMD: str with validated Path to executable command.
        __USER_EDIT_CMD: str with validated Path to executable command.
        __USER_SET_PASS_CMD: str with validated Path to executable command.
        __USER_CHECK_IN_GROUP_CMD: str with validated Path to executable command.
        __USER_REMOVE_GROUP_CMD: str with validated Path to executable command.
        __SUDO_CMD: str with validated Path to executable command (Can be null).
        __KILL_CMD: str with validated Path to executable command (Can be null).
        __validate: do or not command extra validation.
        __task_timeout = timeout for asyncio.wait_for.
        __show_stdout = show proc stdout or not (DEV_NULL if not).

    Attributes:
        user_add_cmd: path to executable command on local fs for user create (`adduser`)
        group_add_cmd: path to executable command on local fs for group create (`addgroup`).
        user_edit_cmd: path to executable command on local fs for user editing (`usermod`).
        user_set_pass_cmd: path to executable command on local fs for user password
            set (`chpasswd`).
        user_check_in_group_cmd: validated path to executable command on local fs for group
            checking (`id -Gn`).
        user_remove_group_cmd: validated path to executable command on local fs
            for user group remove (`gpasswd -d`).
        task_timeout: asyncio.wait_for timeout. Default is 5 sec.
        validate: do or not command extra validation. Default is True.
        show_stdout: show proc stdout or not. Default is False.
        sudo_cmd: nullable path to executable command on local fs for sudo (`sudo`).
        kill_cmd: nullable path to executable command on local fs for kill command (`kill`).
    """

    __USER_ADD_CMD = CommandType('__USER_ADD_CMD')
    __GROUP_ADD_CMD = CommandType('__GROUP_ADD_CMD')
    __USER_EDIT_CMD = CommandType('__USER_EDIT_CMD')
    __USER_SET_PASS_CMD = CommandType('__USER_SET_PASS_CMD')
    __USER_CHECK_IN_GROUP_CMD = CommandType('__USER_CHECK_IN_GROUP_CMD')
    __USER_REMOVE_GROUP_CMD = CommandType('__USER_REMOVE_GROUP_CMD')
    __SUDO_CMD = OptionalCommandType('__SUDO_CMD')
    __KILL_CMD = OptionalCommandType('__KILL_CMD')

    def __init__(self, user_add_cmd: str,
                 group_add_cmd: str,
                 user_edit_cmd: str,
                 user_set_pass_cmd: str,
                 user_check_in_group_cmd: str,
                 user_remove_group_cmd: str,
                 task_timeout: Optional[int] = 5,
                 validate: Optional[bool] = True,
                 show_stdout: Optional[bool] = False,
                 sudo_cmd: Optional[str] = None,
                 kill_cmd: Optional[str] = None):
        """Please see help(VeilAuthPam) for more info."""
        # Commands
        self.__USER_ADD_CMD = user_add_cmd
        self.__GROUP_ADD_CMD = group_add_cmd
        self.__USER_EDIT_CMD = user_edit_cmd
        self.__USER_SET_PASS_CMD = user_set_pass_cmd
        self.__USER_CHECK_IN_GROUP_CMD = user_check_in_group_cmd
        self.__USER_REMOVE_GROUP_CMD = user_remove_group_cmd
        self.__SUDO_CMD = sudo_cmd
        self.__KILL_CMD = kill_cmd
        # Additional
        self.__task_timeout = task_timeout
        self.__validate = validate
        self.__show_stdout = show_stdout

    @property
    def as_sudo(self):
        """If __SUDO_CMD and __KILL_CMD is not null, commands should be with sudo prefix."""
        if self.__SUDO_CMD and not self.__KILL_CMD:
            raise AssertionError('Define a `kill_cmd`, otherwise created processes may be not closed.')  # noqa: E501
        return bool(self.__SUDO_CMD and self.__KILL_CMD)

    @property
    def __possible_commands(self) -> set:
        """Only pre-added commands."""
        result_set = set()
        for attr in dir(self):
            if hasattr(self.__class__, attr) and callable(getattr(self.__class__, attr)):
                continue
            if attr.startswith('__') and attr.endswith('_CMD'):
                result_set.add(self.__getattribute__(attr))
        return result_set

    async def __validate_command(self, cmd: str):
        """Check that cmd in __possible_commands set."""
        if not cmd:
            raise ValueError('{c} should be not empty.')
        if cmd not in self.__possible_commands:
            raise ValueError('{c} execution denied. Try one of:{pc}'.format(c=cmd, pc=self.__possible_commands))  # noqa: E501

    @staticmethod
    async def __escape_command_args(cmd_args: list) -> list:
        """Make shell-escaped cmd arguments."""
        if not cmd_args or not isinstance(cmd_args, list):
            raise ValueError('{c} should be not empty.')
        cmd_args_str = ' '.join(cmd_args)
        return shlex.split(cmd_args_str)

    async def __run_cmd(self, cmd: str, cmd_args: List[str],
                        show_stdout: Optional[bool] = None,
                        as_sudo: Optional[bool] = None) -> VeilResult:
        """Create asyncio.subprocess with __task_timeout.

        cmd: should be a str value of VeilAuthPam.__*_CMD attribute.
        cmd_args: list of cmd str arguments.

        proc.wait() note:
            This method can deadlock when using stdout=PIPE or stderr=PIPE and the child
            process generates so much output that it blocks waiting for the OS pipe
            buffer to accept more data. Use the communicate() method when using pipes to
            avoid this condition.
        """
        # Prepare arguments
        if as_sudo is None:
            as_sudo = self.as_sudo
        if as_sudo and not self.as_sudo:
            raise ValueError('Run as sudo activated, but sudo commands are empty.')
        if show_stdout is None:
            show_stdout = self.__show_stdout

        # validate
        if self.__validate:
            await self.__validate_command(cmd=cmd)
            cmd_args = await self.__escape_command_args(cmd_args=cmd_args)
        if as_sudo:
            cmd_args.insert(0, cmd)
            cmd = self.__SUDO_CMD
        # run subprocess
        try:
            stdout = asyncio.subprocess.PIPE if show_stdout else asyncio.subprocess.DEVNULL
            proc = await asyncio.create_subprocess_exec(cmd, *cmd_args,
                                                        stdout=stdout,
                                                        stderr=asyncio.subprocess.PIPE,
                                                        limit=1000)
            stdout, stderr = await asyncio.wait_for(proc.communicate(), self.__task_timeout)

            return_code = proc.returncode
        except asyncio.TimeoutError:
            return_code = 1
            stderr = None
            stdout = None
            if as_sudo:
                kill_cmd_args = [self.__KILL_CMD, str(proc.pid)]
                kill_proc = await asyncio.create_subprocess_exec(cmd, *kill_cmd_args,
                                                                 stdout=asyncio.subprocess.DEVNULL,  # noqa: E501
                                                                 stderr=asyncio.subprocess.DEVNULL,  # noqa: E501
                                                                 limit=50)  # noqa: E501
                await kill_proc.wait()
            else:
                proc.kill()
                await asyncio.wait_for(proc.wait(), 10)
        # prepare VeilResult
        error_msg = stderr.decode() if stderr else None
        stdout_msg = stdout.decode() if stdout else None
        return_code = 1 if return_code == 0 and stderr else return_code
        return VeilResult(return_code=return_code, error_msg=error_msg, stdout_msg=stdout_msg)

    async def _user_edit(self, username: str, group_add: Optional[str] = None,
                         lock: Optional[bool] = False, unlock: Optional[bool] = False,
                         gecos: Optional[str] = None,
                         expire_date: Optional[str] = None,
                         inactive_period: Optional[int] = None,
                         show_stdout: Optional[bool] = None,
                         as_sudo: Optional[bool] = None
                         ) -> VeilResult:
        """Modify user attributes.

        Arguments:
            username: existing user username
            group_add: additional group to add
            lock: lock user
            unlock: unlock user
            gecos: new gecos value
            expire_date: The date in the format YYYY-MM-DD on which the user account will
                be disabled.
            inactive_period: The number of days after a password expires until the account is
                permanently disabled.
            show_stdout: redefine the class show_stdout argument.
            as_sudo: redefine the class as_sudo argument
        """
        # Prepare and validate command arguments
        cmd_args = ['-u', username]
        if group_add and isinstance(group_add, str):
            cmd_args.append('-a {}'.format(group_add))
        if lock and isinstance(lock, bool):
            cmd_args.append('-L')
        if unlock and isinstance(unlock, bool):
            cmd_args.append('-U')
        if gecos and isinstance(gecos, str):
            # TODO: chfn: name with non-ASCII characters: 'фамилия имя'
            cmd_args.append('-c {}'.format(gecos))
        if expire_date and isinstance(expire_date, str):
            cmd_args.append('-e {}'.format(expire_date))
        if inactive_period and isinstance(inactive_period, int):
            cmd_args.append('-f {}'.format(inactive_period))
        if len(cmd_args) <= 2:
            raise ValueError('No new arguments.')
        # Execute command
        return await self.__run_cmd(cmd=self.__USER_EDIT_CMD,
                                    cmd_args=cmd_args,
                                    show_stdout=show_stdout,
                                    as_sudo=as_sudo)

    async def user_create(self, username: str,
                          group: Optional[str] = None,
                          gecos: Optional[str] = None,
                          show_stdout: Optional[bool] = None,
                          as_sudo: Optional[bool] = None) -> VeilResult:
        """Run self.__ADD_USER_CMD with given username, password and gecos.

        Arguments:
            username: new username
            group: existing group
            gecos: GECOS str (https://en.wikipedia.org/wiki/Gecos_field)
            show_stdout: redefine the class show_stdout argument.
            as_sudo: redefine the class as_sudo argument.
        """
        cmd_args = ['-u', username]
        if group and isinstance(group, str):
            cmd_args.append('-g {}'.format(group))
        if gecos and isinstance(gecos, str):
            # TODO: chfn: name with non-ASCII characters: 'фамилия имя'
            cmd_args.append('-G {}'.format(gecos))
        return await self.__run_cmd(cmd=self.__USER_ADD_CMD,
                                    cmd_args=cmd_args,
                                    show_stdout=show_stdout,
                                    as_sudo=as_sudo)

    async def user_set_password(self, username: str, new_password: str,
                                show_stdout: Optional[bool] = None,
                                as_sudo: Optional[bool] = None) -> VeilResult:
        """Set to a user with username new password.

        Arguments:
            username: str, username of existing user.
            new_password: str, plaintext with new password that should be set to a user.
            show_stdout: redefine the class show_stdout argument.
            as_sudo: redefine the class as_sudo argument.
        """
        cmd_args = ['-u', username, '-p', new_password]
        return await self.__run_cmd(cmd=self.__USER_SET_PASS_CMD,
                                    cmd_args=cmd_args,
                                    show_stdout=show_stdout,
                                    as_sudo=as_sudo)

    async def user_create_new(self, username: str, password: str, group: Optional[str] = None,
                              gecos: Optional[str] = None,
                              show_stdout: Optional[bool] = None,
                              as_sudo: Optional[bool] = None) -> VeilResult:
        """Interface for creating new user.

        Create new user -> Set password to a new user.

        Arguments:
            username: new username
            password: str, plaintext with new password that should be set to a user.
            group: existing group
            gecos: GECOS str (https://en.wikipedia.org/wiki/Gecos_field)
            show_stdout: redefine the class show_stdout argument.
            as_sudo: redefine the class as_sudo argument.

        If return code 969 - user is created, but password set return error.
        """
        user_result = await self.user_create(username=username,
                                             group=group,
                                             gecos=gecos,
                                             show_stdout=show_stdout,
                                             as_sudo=as_sudo)
        if not user_result.success:
            return user_result
        password_result = await self.user_set_password(username=username,
                                                       new_password=password,
                                                       show_stdout=show_stdout,
                                                       as_sudo=as_sudo)
        if not password_result.success:
            # pseudo-unique return code
            return VeilResult(return_code=969,
                              error_msg=password_result.error_msg,
                              stdout_msg=None)
        return VeilResult(return_code=0, error_msg=None, stdout_msg=None)

    async def user_set_gecos(self, username: str, gecos: str,
                             show_stdout: Optional[bool] = None,
                             as_sudo: Optional[bool] = None) -> VeilResult:
        """Set new GECOS value for a user with username."""
        return await self._user_edit(username=username,
                                     gecos=gecos,
                                     show_stdout=show_stdout,
                                     as_sudo=as_sudo)

    async def user_add_group(self, username: str, group: str,
                             show_stdout: Optional[bool] = None,
                             as_sudo: Optional[bool] = None) -> VeilResult:
        """Add to a user additional group."""
        return await self._user_edit(username=username,
                                     group_add=group,
                                     show_stdout=show_stdout,
                                     as_sudo=as_sudo)

    async def user_lock(self, username: str,
                        show_stdout: Optional[bool] = None,
                        as_sudo: Optional[bool] = None) -> VeilResult:
        """Lock a user with the given username."""
        return await self._user_edit(username=username,
                                     lock=True,
                                     show_stdout=show_stdout,
                                     as_sudo=as_sudo)

    async def user_unlock(self, username: str,
                          show_stdout: Optional[bool] = None,
                          as_sudo: Optional[bool] = None) -> VeilResult:
        """Unlock a user with the given username."""
        return await self._user_edit(username=username,
                                     unlock=True,
                                     show_stdout=show_stdout,
                                     as_sudo=as_sudo)

    async def user_remove_group(self, username: str, group: str,
                                show_stdout: Optional[bool] = None,
                                as_sudo: Optional[bool] = None) -> VeilResult:
        """Remove existing user from a group members."""
        cmd_args = ['-u', username, '-g', group]
        return await self.__run_cmd(cmd=self.__USER_REMOVE_GROUP_CMD,
                                    cmd_args=cmd_args,
                                    show_stdout=show_stdout,
                                    as_sudo=as_sudo)

    async def user_in_group(self, username: str, group: str,
                            as_sudo: Optional[bool] = None) -> bool:
        """Check that user in a group."""
        cmd_args = ['-u', username, '-g', group]
        check_result = await self.__run_cmd(cmd=self.__USER_CHECK_IN_GROUP_CMD,
                                            cmd_args=cmd_args,
                                            show_stdout=True,
                                            as_sudo=as_sudo)
        if check_result.success and check_result.stdout_msg.strip() != '0':
            return True
        return False

    async def group_create(self, group: str,
                           show_stdout: Optional[bool] = None,
                           as_sudo: Optional[bool] = None) -> VeilResult:
        """Create new group."""
        cmd_args = ['-g', group]
        return await self.__run_cmd(cmd=self.__GROUP_ADD_CMD,
                                    cmd_args=cmd_args,
                                    show_stdout=show_stdout,
                                    as_sudo=as_sudo)

    async def user_authenticate(self, username: str, password: str) -> VeilResult:
        """Run system authentication method via libpam."""
        if pam is None:
            raise RuntimeError('Please install `python-pam`')  # pragma: no cover
        __PAM = pam.pam()
        loop = asyncio.get_event_loop()
        aio_task = asyncio.ensure_future(loop.run_in_executor(None,
                                                              __PAM.authenticate,
                                                              username,
                                                              password))
        try:
            result = await asyncio.wait_for(aio_task, timeout=self.__task_timeout)
        except asyncio.TimeoutError:
            result = False
        # prepare VeilResult
        stdout_msg = __PAM.reason if result else None
        error_msg = __PAM.reason if not result else None
        return_code = __PAM.code
        return VeilResult(return_code=return_code, error_msg=error_msg, stdout_msg=stdout_msg)
