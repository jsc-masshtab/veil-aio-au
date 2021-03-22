[![Python 3.5](https://img.shields.io/badge/python-3.5-blue.svg)](https://www.python.org/downloads/release/python-350/)
[![Python 3.6](https://img.shields.io/badge/python-3.6-blue.svg)](https://www.python.org/downloads/release/python-360/)
[![Python 3.7](https://img.shields.io/badge/python-3.7-blue.svg)](https://www.python.org/downloads/release/python-370/)
[![Coverage](https://img.shields.io/static/v1?label=coverage&message=0%&color=red)](https://coverage.readthedocs.io/en/coverage-5.1/)

# veil-aio-au

## Установка
Проект доступен в PyPi, можете воспользоваться поддерживаемым пакетным менеджером, например, **pip**
`pip install veil-aio-au`

## Использование

### Команды для запуска на системе
Настоятельно не рекомендуется использовать напрямую системные команды, т.к. для корректной работы требуется возможность
запуска команды с **sudo** без подтверждения пароля. В качестве примера в разделе **bash** размещены bash-скрипты
с интерфейсами вызова.

### Настройки
Учитывая особенности вызова команд, предусмотрена дополнительная валидация аргументов и исполняемых команд.
Если пользовательский ввод исключен, можно отключить валидацию аргументов параметром **validate**.

#### Перечень аргументов
```
task_timeout: время ожидания выполнения команд (5 сек по умолчанию)
user_add_cmd: полный путь до команды создания пользователя (например, adduser)
group_add_cmd: полный путь до команды создания группы (например, addgroup)
user_edit_cmd: полный путь до команды редактирования пользователя (например, usermod)
user_set_pass_cmd: полный путь до команды задания пароля (например, chpasswd)
user_check_in_group_cmd: полный путь до команды проверки нахождения в группе (например, id -Gn)
user_remove_group_cmd: полный путь до команды удаления из группы (например, gpasswd -d)
sudo_cmd: полный путь до команды sudo (например, /usr/bin/sudo). Если пустой - команды запускаются без доп.префикса sudo.
kill_cmd: полный путь до команды которой будут завершаться процессы (например, kill). Обязателен в случае заполнения sudo_cmd, может быть пустым.
validate: включить или отключить дополнительную валидацию аргументов (вкл по умолчанию)
show_stdout: выводить stdout для процессов или нет. (выкл по умолчанию)

```
~~~~
#### Примеры
```
auth_class = VeilAuthPam(task_timeout=5,
                         user_add_cmd='bash/adduser_bi.sh',
                         group_add_cmd='bash/addgroup_bi.sh',
                         user_edit_cmd='bash/edituser_bi.sh',
                         user_set_pass_cmd='bash/set_pass_bi.sh',
                         user_check_in_group_cmd='bash/check_in_group_bi.sh',
                         user_remove_group_cmd='bash/remove_user_group_bi.sh',
                         sudo_cmd='/bin/sudo'
                         )
                         
auth_result = await auth_class.user_authenticate(username='user', password='qqq')
# >>> return code: 7, msg: Authentication failure
create_result = await auth_class.user_create_new(username='user', password='qwe123')
# >>> return code: 0, msg: None
create_result = await auth_class.user_create_new(username='user; /bin/rm -rf /home/devalv/tmp', password='peka')
# >>> return code: 1, msg: Unknown arguments: /bin/rm
check_in_group_result = await auth_class.user_in_group('devalv', 'vdi-web-admin', use_sudo=False)
# >>> True
# Disable as_sudo class attr for user_create_new cmd.
create_result = await auth_class.user_create_new(username='user', password='qwe123', as_sudo=False)
# On default system you`ll need to run cmd with sudo prefix.
# >>> return code: 1, msg: sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper

```
### Документация
Готовые примеры можно посмотреть в main.py репозитория, более подробное доступна через help, например, 
help(VeilAuthPam.user_authenticate).

### Запуск тестов


### Сборка
rm -rf dist/ build/ && python setup.py sdist bdist_wheel

## Как принять участие в проекте
Сделайте форк, внесите свои изменения в отдельной ветке, внесите свои изменения, запустите тесты и разместите PR/MR.