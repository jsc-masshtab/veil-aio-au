# -*- coding: utf-8 -*-
"""Temporary runner."""
import asyncio
from veil_aio_au import VeilAuthPam


async def simple_main():

    auth_class = VeilAuthPam(task_timeout=5,
                             user_add_cmd='bash/adduser_bi.sh',
                             group_add_cmd='bash/addgroup_bi.sh',
                             user_edit_cmd='bash/edituser_bi.sh',
                             user_set_pass_cmd='bash/set_pass_bi.sh',
                             user_check_in_group_cmd='bash/check_in_group_bi.sh',
                             user_remove_group_cmd='bash/remove_user_group_bi.sh',
                             )
    auth_result = await auth_class.user_authenticate(username='user', password='qqq')
    # >>> return code: 7, msg: Authentication failure
    create_result = await auth_class.user_create_new(username='user', password='qwe123')
    # >>> return code: 0, msg: None
    create_result = await auth_class.user_create_new(username='user; /bin/rm -rf /home/devalv/tmp', password='peka')
    # >>> return code: 1, msg: Unknown arguments: /bin/rm

loop = asyncio.get_event_loop()
loop.run_until_complete(simple_main())
loop.close()
