# -*- coding: utf-8 -*-

import asyncio
from pathlib import Path
import stat
from typing import Optional, List
import shlex

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
            raise TypeError('{val} is not a {val_type}'.format(val=value, val_type=self.value_type))
        value = Path(value)
        if not value.is_file():
            raise FileExistsError('{file_path} is not a file.'.format(file_path=value))
        if not self.user_executable(value):
            raise PermissionError('{file_path} can`t be executed by user.'.format(file_path=value))
        instance.__dict__[self.name] = str(value)

    def __get__(self, instance, class_) -> str:
        """Return attribute value."""
        return instance.__dict__[self.name]


class ReturnDict:
    """VeilAuthPam operation result.

    Attributes:
        return_code: all instead of 0 is an error.
        error_msg: stderr value.
        stdout_msg: stdout value.
    """

    def __init__(self, return_code: int, error_msg: str, stdout_msg: str):
        self.return_code = return_code
        self.error_msg = error_msg
        self.stdout_msg = stdout_msg

    @property
    def success(self):
        """If no information about errors - operation result is success."""
        return bool(self.return_code == 0 and not self.error_msg)

    def __str__(self):
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

    Attributes:
        user_add_cmd: path to executable command on local fs for user create (`adduser`)
        group_add_cmd: path to executable command on local fs for group create (`addgroup`).
        user_edit_cmd: path to executable command on local fs for user editing (`usermod`).
        user_set_pass_cmd: path to executable command on local fs for user password set (`chpasswd`).
        user_check_in_group_cmd: validated path to executable command on local fs for group checking (`id -Gn`).
        user_remove_group_cmd: validated path to executable command on local fs for user group remove (`gpasswd -d`).
        task_timeout: asyncio.wait_for timeout.
        validate: do or not command extra validation.
    """

    __USER_ADD_CMD = CommandType('__USER_ADD_CMD')
    __GROUP_ADD_CMD = CommandType('__GROUP_ADD_CMD')
    __USER_EDIT_CMD = CommandType('__USER_EDIT_CMD')
    __USER_SET_PASS_CMD = CommandType('__USER_SET_PASS_CMD')
    __USER_CHECK_IN_GROUP_CMD = CommandType('__USER_CHECK_IN_GROUP_CMD')
    __USER_REMOVE_GROUP_CMD = CommandType('__USER_REMOVE_GROUP_CMD')

    def __init__(self, user_add_cmd: str,
                 group_add_cmd: str,
                 user_edit_cmd: str,
                 user_set_pass_cmd: str,
                 user_check_in_group_cmd: str,
                 user_remove_group_cmd: str,
                 task_timeout: Optional[int] = 5,
                 validate: bool = True):
        """Please see help(VeilAuthPam) for more info."""
        self.__USER_ADD_CMD = user_add_cmd
        self.__GROUP_ADD_CMD = group_add_cmd
        self.__USER_EDIT_CMD = user_edit_cmd
        self.__USER_SET_PASS_CMD = user_set_pass_cmd
        self.__USER_CHECK_IN_GROUP_CMD = user_check_in_group_cmd
        self.__USER_REMOVE_GROUP_CMD = user_remove_group_cmd
        self.__task_timeout = task_timeout
        self.__validate = validate

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
            raise ValueError('{c} execution denied. Try one of:{pc}'.format(c=cmd, pc=self.__possible_commands))

    @staticmethod
    async def __escape_command_args(cmd_args: list) -> list:
        """"""
        if not cmd_args or not isinstance(cmd_args, list):
            raise ValueError('{c} should be not empty.')
        cmd_args_str = ' '.join(cmd_args)
        return shlex.split(cmd_args_str)

    async def __run_cmd(self, cmd: str, cmd_args: List[str]) -> ReturnDict:
        """Create asyncio.subprocess with __task_timeout.

        cmd: should be a str value of VeilAuthPam.__*_CMD attribute.
        cmd_args: list of cmd str arguments.

        Note:
            proc.stdout always will be None.
        """
        # TODO: sudo intercept output. what will be for a next call?
        # validate
        if self.__validate:
            await self.__validate_command(cmd=cmd)
            cmd_args = await self.__escape_command_args(cmd_args=cmd_args)
        # run subprocess
        try:
            proc = await asyncio.create_subprocess_exec(cmd, *cmd_args,
                                                        stdout=asyncio.subprocess.DEVNULL,
                                                        stderr=asyncio.subprocess.PIPE,
                                                        limit=1000)
            stdout, stderr = await asyncio.wait_for(proc.communicate(), self.__task_timeout)

            return_code = proc.returncode
        except asyncio.TimeoutError:
            return_code = 1
            stderr = None
            stdout = None
            proc.kill()
            """
            Note
            This method can deadlock when using stdout=PIPE or stderr=PIPE and the child process generates so much
            output that it blocks waiting for the OS pipe buffer to accept more data. Use the communicate() method
            when using pipes to avoid this condition.
            """
            await asyncio.wait_for(proc.wait(), 10)
        # prepare ReturnDict
        error_msg = stderr.decode() if stderr else None
        stdout_msg = stdout.decode() if stdout else None
        return_code = 1 if return_code == 0 and stderr else return_code
        return ReturnDict(return_code=return_code, error_msg=error_msg, stdout_msg=stdout_msg)

    async def _user_edit(self, username: str, group_add: Optional[str] = None,
                         lock: Optional[bool] = False, unlock: Optional[bool] = False,
                         gecos: Optional[str] = None,
                         expire_date: Optional[str] = None,
                         inactive_period: Optional[int] = None,
                         ) -> ReturnDict:
        """Modify user attributes.

        Arguments:
            username: existing user username
            group_add: additional group to add
            lock: lock user
            unlock: unlock user
            gecos: new gecos value
            expire_date: The date in the format YYYY-MM-DD on which the user account will be disabled.
            inactive_period: The number of days after a password expires until the account is permanently disabled.
        """
        # Prepare and validate command arguments
        cmd_args = ['-u', username]
        if group_add and isinstance(group_add, str):
            cmd_args.append('-a', group_add)
        if lock and isinstance(lock, bool):
            cmd_args.append('-L')
        if unlock and isinstance(unlock, bool):
            cmd_args.append('-U')
        if gecos and isinstance(gecos, str):
            cmd_args.append('-c', gecos)
        if expire_date and isinstance(expire_date, str):
            cmd_args.append('-e', expire_date)
        if inactive_period and isinstance(inactive_period, int):
            cmd_args.append('-f', inactive_period)
        if len(cmd_args) <= 2:
            raise ValueError('No new arguments.')
        # Execute command
        return await self.__run_cmd(cmd=self.__USER_EDIT_CMD, cmd_args=cmd_args)

    async def user_create(self, username: str, group: Optional[str] = None, gecos: Optional[str] = None) -> ReturnDict:
        """Run self.__ADD_USER_CMD with given username, password and gecos.

        Arguments:
            username: new username
            group: existing group
            gecos: GECOS str (https://en.wikipedia.org/wiki/Gecos_field)
        """
        cmd_args = ['-u', username]
        if group and isinstance(group, str):
            cmd_args.append('-g', group)
        if gecos and isinstance(gecos, str):
            cmd_args.append('-G', gecos)
        return await self.__run_cmd(cmd=self.__USER_ADD_CMD, cmd_args=cmd_args)

    async def user_set_password(self, username: str, new_password: str) -> ReturnDict:
        """Set to a user with username new password.

        Arguments:
            username: str, username of existing user.
            new_password: str, plaintext with new password that should be set to a user.
        """
        cmd_args = ['-u', username, '-p', new_password]
        return await self.__run_cmd(cmd=self.__USER_SET_PASS_CMD, cmd_args=cmd_args)

    async def user_create_new(self, username: str, password: str, group: Optional[str] = None,
                              gecos: Optional[str] = None) -> ReturnDict:
        """Interface for creating new user.

        Create new user -> Set password to a new user.

        Arguments:
            username: new username
            password: str, plaintext with new password that should be set to a user.
            group: existing group
            gecos: GECOS str (https://en.wikipedia.org/wiki/Gecos_field)
        """
        user_result = await self.user_create(username=username, group=group, gecos=gecos)
        if not user_result.success:
            return user_result
        password_result = await self.user_set_password(username=username, new_password=password)
        if not password_result.success:
            return password_result
        return ReturnDict(return_code=0, error_msg=None, stdout_msg=None)

    async def user_set_gecos(self, username: str, gecos: str) -> ReturnDict:
        """Set new GECOS value for a user with username."""
        return await self._user_edit(username=username, gecos=gecos)

    async def user_add_group(self, username: str, group: str) -> ReturnDict:
        """Add to a user additional group."""
        return await self._user_edit(username=username, group=group)

    async def user_lock(self, username: str) -> ReturnDict:
        """Lock a user with the given username."""
        return await self._user_edit(username=username, lock=True)

    async def user_unlock(self, username: str) -> ReturnDict:
        """Unlock a user with the given username."""
        return await self._user_edit(username=username, unlock=True)

    async def user_remove_group(self, username: str, group: str) -> ReturnDict:
        """Remove existing user from a group members."""
        cmd_args = ['-u', username, '-g', group]
        return await self.__run_cmd(cmd=self.__USER_REMOVE_GROUP_CMD, cmd_args=cmd_args)

    async def user_in_group(self, username: str, group: str) -> bool:
        """Check that user in a group."""
        cmd_args = ['-u', username, '-g', group]
        check_result = await self.__run_cmd(cmd=self.__USER_CHECK_IN_GROUP_CMD, cmd_args=cmd_args)
        if check_result.success:
            return True
        return False

    async def group_create(self, group: str) -> ReturnDict:
        """Create new group."""
        cmd_args = ['-g', group]
        return await self.__run_cmd(cmd=self.__GROUP_ADD_CMD, cmd_args=cmd_args)

    async def user_authenticate(self, username: str, password: str) -> ReturnDict:
        """Run system authentication method via libpam."""
        if pam is None:
            raise RuntimeError('Please install `python-pam`')  # pragma: no cover
        __PAM = pam.pam()
        loop = asyncio.get_event_loop()
        aio_task = asyncio.ensure_future(loop.run_in_executor(None, __PAM.authenticate, username, password))
        try:
            result = await asyncio.wait_for(aio_task, timeout=self.__task_timeout)
        except asyncio.TimeoutError:
            result = False
        # prepare ReturnDict
        stdout_msg = __PAM.reason if result else None
        error_msg = __PAM.reason if not result else None
        return_code = __PAM.code
        return ReturnDict(return_code=return_code, error_msg=error_msg, stdout_msg=stdout_msg)
