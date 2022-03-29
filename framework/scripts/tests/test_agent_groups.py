# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from getopt import GetoptError
from unittest.mock import call, patch
import pytest
from wazuh.core.exception import WazuhError

import scripts.agent_groups as agent_groups


@patch('scripts.agent_groups.exit')
def test_signal_handler(mock_exit):
    """Check if exit is called in signal_handler function."""
    agent_groups.signal_handler('test', 'test')
    mock_exit.assert_called_once_with(1)


@patch('builtins.print')
def test_show_groups(print_mock):
    """Check that the show_groups function displays the groups properly."""
    class AgentMock:
        def __init__(self, q=None):
            self.testing_key = 'testing_value'

        def to_dict(self):
            return {'affected_items': [{'name': 'a', 'count': '1'}, {'name': 'b', 'count': '2'}],
                    'total_affected_items': '3'}

    with patch('scripts.agent_groups.agent.get_agent_groups', side_effect=AgentMock) as get_agent_groups_mock:
        with patch('scripts.agent_groups.agent.get_agents', side_effect=AgentMock) as get_agents_mock:
            agent_groups.show_groups()
            get_agent_groups_mock.assert_called_once()
            get_agents_mock.assert_called_once_with(q='id!=000;group=null')
            print_mock.assert_has_calls([call('Groups (3):'), call('  a (1)'),
                                         call('  b (2)'), call('Unassigned agents: 3.')])


@patch('builtins.print')
def test_show_group(print_mock):
    """Check that the show_group function shows the groups to which an agent belongs."""
    class AgentMock:
        counter = 1
        def __init__(self, agent_list=None):
            self.testing_key = 'testing_value'

        def to_dict(self):
            return {'affected_items': [{'name': 'a', 'id': 1}, {'name': 'b', 'id': 2}],
                    'failed_items': {'a': 'b'}, 'total_affected_items': AgentMock.counter}

    with patch('scripts.agent_groups.agent.get_agents', side_effect=AgentMock) as get_agents_mock:
        agent_groups.show_group(0)
        get_agents_mock.assert_called_once_with(agent_list=[0])
        print_mock.assert_has_calls([call("The agent 'a' with ID '1' belongs to groups: Null.")])
        print_mock.reset_mock()

        AgentMock.counter = 0
        agent_groups.show_group(0)
        print_mock.assert_has_calls([call('a')])


@patch('builtins.print')
def test_show_synced_agent(print_mock):
    """Check that the synchronization status of an agent's groups is returned correctly."""
    class AgentMock:
        counter = 0
        def __init__(self, agent_list=None):
            self.testing_key = 'testing_value'

        def to_dict(self):
            return {'affected_items': [{'name': 'a', 'id': 1, 'synced': True}, {'name': 'b', 'id': 2, 'synced': False}],
                    'failed_items': {'a': 'b'}, 'total_affected_items': AgentMock.counter}

    with patch('scripts.agent_groups.agent.get_agents_sync_group', side_effect=AgentMock) as get_agents_sync_group_mock:
        agent_groups.show_synced_agent(0)
        get_agents_sync_group_mock.assert_called_once_with(agent_list=[0])
        print_mock.assert_has_calls([call('a')])
        print_mock.reset_mock()
        AgentMock.counter = 1
        agent_groups.show_synced_agent(0)
        print_mock.assert_has_calls([call("Agent '0' is synchronized. ")])


@patch('builtins.print')
def test_show_agents_with_group(print_mock):
    """Check that agents belonging to a certain group are returned."""
    class AgentMock:
        counter = 0
        def __init__(self, group_list=None, limit=None):
            assert group_list == ['testing']
            self.testing_key = 'testing_value'

        def to_dict(self):
            return {'affected_items': [{'name': 'a', 'id': 1, 'synced': True}, {'name': 'b', 'id': 2, 'synced': False}],
                    'failed_items': {'a': 'b'}, 'total_affected_items': AgentMock.counter}

    with patch('scripts.agent_groups.agent.get_agents_in_group', side_effect=AgentMock) as get_agents_in_group_mock:
        agent_groups.show_agents_with_group(group_id='testing')
        get_agents_in_group_mock.assert_called_once_with(group_list=['testing'], limit=None)
        print_mock.assert_has_calls([call("No agents found in group 'testing'.")])
        print_mock.reset_mock()
        AgentMock.counter = 1
        agent_groups.show_agents_with_group(group_id='testing')
        print_mock.assert_has_calls([call("1 agent(s) in group 'testing':"),
                                     call('  ID: 1  Name: a.'), call('  ID: 2  Name: b.')])


@patch('builtins.print')
def test_show_group_files(print_mock):
    """Check that the files of the specified group are returned."""
    class AgentMock:
        counter = 0
        def __init__(self, group_list=None, limit=None):
            assert group_list == ['testing']
            self.testing_key = 'testing_value'

        def to_dict(self):
            return {'affected_items': [{'filename': 'a', 'hash': 'aa'}, {'filename': 'b', 'hash': 'bb'}],
                    'failed_items': {'a': 'b'}, 'total_affected_items': AgentMock.counter}

    with patch('scripts.agent_groups.agent.get_group_files', side_effect=AgentMock) as get_agents_in_group_mock:
        agent_groups.show_group_files(group_id='testing')
        get_agents_in_group_mock.assert_called_once_with(group_list=['testing'])
        print_mock.assert_has_calls([call("0 files for 'testing' group:"), call('  a  [aa]'), call('  b  [bb]')])
        print_mock.reset_mock()
        AgentMock.counter = 1
        agent_groups.show_group_files(group_id='testing')
        print_mock.assert_has_calls([call("1 files for 'testing' group:"), call('  a  [aa]'), call('  b  [bb]')])


@patch('builtins.print')
def test_unset_group(print_mock):
    """Check the unassignment of one or more groups for an agent."""
    class WazuhResultMock:
        def __init__(self, affected_items):
            self._affected_items = affected_items if int(affected_items[0]) > 0 else []

    class AgentMock:
        def __init__(self):
            self.testing_key = 'testing_value'

        @staticmethod
        def unset_single_group_agent(agent_id, group_id):
            assert agent_id == 99
            assert group_id == 'testing'

            return "unset_single_group_agent"

    def remove_agent_from_groups_mock(agent_list):
        return WazuhResultMock(affected_items=agent_list)

    with patch('scripts.agent_groups.core_agent.Agent', AgentMock):
        with patch('scripts.agent_groups.get_stdin', return_value='y') as get_stdin_mock:
            agent_groups.unset_group(agent_id=99, group_id='testing')
            get_stdin_mock.assert_has_calls([call("Do you want to delete the group 'testing' of agent '99'? [y/N]: ")])
            print_mock.assert_has_calls([call("unset_single_group_agent")])
            print_mock.reset_mock()
            get_stdin_mock.reset_mock()

            with patch('scripts.agent_groups.remove_agent_from_groups', remove_agent_from_groups_mock):
                agent_groups.unset_group(agent_id='999')
                get_stdin_mock.assert_has_calls([call("Do you want to delete all groups of agent '999'? [y/N]: ")])
                print_mock.assert_has_calls(
                    [call("Agent '999' removed from '999'. Agent reassigned to group default.")])
                print_mock.reset_mock()

                agent_groups.unset_group(agent_id='0', quiet=True)
                print_mock.assert_has_calls([call("Agent '0' is only assigned to group default.")])
                print_mock.reset_mock()

        with patch('scripts.agent_groups.get_stdin', return_value='n') as get_stdin_mock:
            agent_groups.unset_group(agent_id=99, group_id='testing')
            get_stdin_mock.assert_has_calls([call("Do you want to delete the group 'testing' of agent '99'? [y/N]: ")])
            print_mock.assert_has_calls([call("Cancelled.")])


@patch('builtins.print')
def test_remove_group(print_mock):
    """Check that the specified group is removed."""
    class AgentMock:
        counter = 0
        def __init__(self, group_list):
            self.testing_key = 'testing_value'

        def to_dict(self):
            return {'dikt': {'affected_agents': ['agent0', 'agent1'] if AgentMock.counter == 1 else []},
                    'failed_items': {'a': 'b'}, 'total_affected_items': AgentMock.counter}

    with patch('scripts.agent_groups.agent.delete_groups', side_effect=AgentMock):
        with patch('scripts.agent_groups.get_stdin', return_value='y') as get_stdin_mock:
            agent_groups.remove_group(group_id='testing')
            get_stdin_mock.assert_has_calls([call("Do you want to remove the 'testing' group? [y/N]: ")])
            print_mock.assert_has_calls([call('a'), call('')])
            print_mock.reset_mock()
            get_stdin_mock.reset_mock()

            AgentMock.counter = 2
            agent_groups.remove_group(group_id='testing', quiet=True)
            print_mock.assert_has_calls([call('Group testing removed.\nNo affected agents.')])
            print_mock.reset_mock()
            get_stdin_mock.reset_mock()

            AgentMock.counter = 1
            agent_groups.remove_group(group_id='testing', quiet=True)
            print_mock.assert_has_calls([call('Group testing removed.\nAffected agents: agent0, agent1.')])

        with patch('scripts.agent_groups.get_stdin', return_value='n'):
            agent_groups.remove_group(group_id='testing')
            print_mock.assert_has_calls([call('Cancelled.')])


@patch('builtins.print')
def test_set_group(print_mock):
    """Check that it adds the specified group to the agent information."""
    class AgentMock:
        counter = 0
        def __init__(self, agent_list, group_list, replace):
            self.testing_key = 'testing_value'

        def to_dict(self):
            return {'dikt': {'affected_agents': ['agent0', 'agent1'] if AgentMock.counter == 1 else []},
                    'failed_items': {'a': 'b'}, 'total_affected_items': AgentMock.counter}

    with patch('scripts.agent_groups.agent.assign_agents_to_group', side_effect=AgentMock):
        with patch('scripts.agent_groups.get_stdin', return_value='y') as get_stdin_mock:
            agent_groups.set_group(agent_id=1, group_id='testing')
            get_stdin_mock.assert_has_calls(
                [call("Do you want to add the group 'testing' to the agent '001'? [y/N]: ")])
            print_mock.assert_has_calls([call('a')])
            print_mock.reset_mock()
            get_stdin_mock.reset_mock()

            AgentMock.counter = 1
            agent_groups.set_group(agent_id=2, group_id='testing', quiet=True)
            print_mock.assert_has_calls([call("Group 'testing' added to agent '002'.")])
            print_mock.reset_mock()
            get_stdin_mock.reset_mock()

        with patch('scripts.agent_groups.get_stdin', return_value='n'):
            agent_groups.set_group(agent_id=3, group_id='testing')
            print_mock.assert_has_calls([call('Cancelled.')])


@patch('builtins.print')
def test_create_group(print_mock):
    """Check the successful group creation."""
    class AgentMock:
        def __init__(self, group_list):
            self.dikt = {'message': group_list}

    with patch('scripts.agent_groups.agent.create_group', side_effect=AgentMock):
        with patch('scripts.agent_groups.get_stdin', return_value='y') as get_stdin_mock:
            agent_groups.create_group(group_id='testing')
            get_stdin_mock.assert_has_calls([call("Do you want to create the group 'testing'? [y/N]: ")])
            print_mock.assert_has_calls([call('testing')])
            print_mock.reset_mock()
            get_stdin_mock.reset_mock()

            agent_groups.create_group(group_id='testing', quiet=True)
            print_mock.assert_has_calls([call('testing')])
            print_mock.reset_mock()
            get_stdin_mock.reset_mock()

        with patch('scripts.agent_groups.get_stdin', return_value='n'):
            agent_groups.create_group(group_id='testing')
            print_mock.assert_has_calls([call('Cancelled.')])


@patch('builtins.print')
@patch('scripts.agent_groups.basename', return_value="mock basename")
def test_usage(basename_mock, print_mock):
    """Test if the usage is being correctly printed."""
    msg = """
    {0} [ -l [ -g group_id ] | -c -g group_id | -a (-i agent_id -g group_id | -g group_id) [-q] [-f] | -s -i agent_id | -S -i agent_id | -r (-g group_id | -i agent_id) [-q] ]

    Usage:
    \t-l                                    # List all groups
    \t-l -g group_id                        # List agents in group
    \t-c -g group_id                        # List configuration files in group
    \t
    \t-a -i agent_id -g group_id [-q] [-f]  # Add group to agent
    \t-r -i agent_id [-q] [-g group_id]     # Remove all groups from agent [or single group]
    \t-s -i agent_id                        # Show group of agent
    \t-S -i agent_id                        # Show sync status of agent
    \t
    \t-a -g group_id [-q]                   # Create group
    \t-r -g group_id [-q]                   # Remove group


    Params:
    \t-l, --list
    \t-c, --list-files
    \t-a, --add-group
    \t-f, --force-single-group
    \t-s, --show-group
    \t-S, --show-sync
    \t-r, --remove-group

    \t-i, --agent-id
    \t-g, --group

    \t-q, --quiet (no confirmation)
    \t-d, --debug
    """.format(basename_mock.return_value)

    agent_groups.usage()
    print_mock.assert_called_once_with(msg)

    basename_mock.assert_called_once_with(sys.argv[0])


@patch('scripts.agent_groups.exit')
@patch('builtins.print')
def test_invalid_option(print_mock, exit_mock):
    """Check the proper functioning of the function in charge of
    notifying the user in case of error with the CLI options."""
    agent_groups.invalid_option()
    print_mock.assert_has_calls([call('Invalid options.'), call("Try '--help' for more information.\n")])
    exit_mock.assert_called_once_with(1)
    print_mock.reset_mock()
    exit_mock.reset_mock()

    agent_groups.invalid_option(msg='test')
    print_mock.assert_has_calls([call('Invalid options: test.'), call("Try '--help' for more information.\n")])
    exit_mock.assert_called_once_with(1)


@patch('scripts.agent_groups.exit', side_effect=exit)
@patch('scripts.agent_groups.remove_group')
@patch('scripts.agent_groups.unset_group')
@patch('scripts.agent_groups.show_synced_agent')
@patch('scripts.agent_groups.show_group')
@patch('scripts.agent_groups.invalid_option')
@patch('scripts.agent_groups.create_group')
@patch('scripts.agent_groups.set_group')
@patch('scripts.agent_groups.show_group_files')
@patch('scripts.agent_groups.show_agents_with_group')
@patch('scripts.agent_groups.show_groups')
@patch('scripts.agent_groups.usage')
@patch('builtins.print')
def test_main(print_mock, usage_mock, show_groups_mock, show_agents_with_group_mock, show_group_files_mock,
              set_group_mock, create_group_mock, invalid_option_mock, show_group_mock, show_synced_agent_mock,
              unset_group_mock, remove_group_mock, exit_mock):
    """Test the main function."""
    # No arguments
    with pytest.raises(SystemExit):
        agent_groups.main()
        show_groups_mock.assert_called()

    # getopt raises a GetoptError
    with patch('scripts.agent_groups.getopt', side_effect=GetoptError('testing_error')) as getopt_mock:
        with pytest.raises(SystemExit):
            agent_groups.main()
        getopt_mock.assert_called_once()
        print_mock.assert_called_with("testing_error\nTry '--help' for more information.")
        exit_mock.assert_called_with(1)
        print_mock.reset_mock()
        exit_mock.reset_mock()

    # n_args > 5 or n_actions > 1
    with patch('scripts.agent_groups.getopt', return_value=([('-l', 'None'), ('-l', 'None'), ('-l', 'None'),
                                                             ('-l', 'None'), ('-l', 'None'), ('-l', 'None')], None)):
        agent_groups.main()
        invalid_option_mock.assert_called_once_with("Bad argument combination.")
        invalid_option_mock.reset_mock()

    with patch('scripts.agent_groups.getopt', return_value=([('-l', 'None'), ('-c', 'None')], None)):
        agent_groups.main()
        invalid_option_mock.assert_called_once_with("Bad argument combination.")
        invalid_option_mock.reset_mock()
        show_groups_mock.reset_mock()

    # -h
    with patch('scripts.agent_groups.getopt', return_value=([('-h', 'None')], None)):
        with pytest.raises(SystemExit):
            agent_groups.main()
        usage_mock.assert_called_once()
        exit_mock.assert_called_once_with(0)

    # -d
    with patch('scripts.agent_groups.getopt', return_value=([('-d', 'None')], None)):
        assert agent_groups.debug == False
        agent_groups.main()
        assert agent_groups.debug == True
        invalid_option_mock.reset_mock()

    # -l
    with patch('scripts.agent_groups.getopt', return_value=([('-l', 'None')], None)):
        agent_groups.main()
        show_groups_mock.assert_called_once()

    # -l -g
    with patch('scripts.agent_groups.getopt', return_value=([('-l', 'None'), ('-g', 'group')], None)):
        agent_groups.main()
        show_agents_with_group_mock.assert_called_once_with('group')

    # -c --list-files
    with patch('scripts.agent_groups.getopt', return_value=([('-c', 'None')], None)):
        agent_groups.main()
        invalid_option_mock.assert_called_once_with('Missing group.')
        invalid_option_mock.reset_mock()

    # -c -g
    with patch('scripts.agent_groups.getopt', return_value=([('-c', 'None'), ('-g', 'group')], None)):
        agent_groups.main()
        show_group_files_mock.assert_called_once_with('group')

    # -a -i agent_id -g group_id
    with patch('scripts.agent_groups.getopt', return_value=([('-a', 'None'), ('-i', '001'), ('-g', 'group1')], None)):
        agent_groups.main()
        set_group_mock.assert_called_once_with('001', 'group1', False, False)
        set_group_mock.reset_mock()

    # -a -i agent_id -g group_id -f
    with patch('scripts.agent_groups.getopt',
               return_value=([('-a', 'None'), ('-i', '001'), ('-g', 'group1'), ('-f', 'None')], None)):
        agent_groups.main()
        set_group_mock.assert_called_once_with('001', 'group1', False, True)
        set_group_mock.reset_mock()

    # -a -i agent_id -g group_id -f -q
    with patch('scripts.agent_groups.getopt',
               return_value=([('-a', 'None'), ('-i', '001'), ('-g', 'group1'), ('-f', 'None'), ('-q', 'None')], None)):
        agent_groups.main()
        set_group_mock.assert_called_once_with('001', 'group1', True, True)

    # -a -g group_id
    with patch('scripts.agent_groups.getopt', return_value=([('-a', 'None'), ('-g', 'group1')], None)):
        agent_groups.main()
        create_group_mock.assert_called_once_with('group1', False)
        create_group_mock.reset_mock()

    # -a -g group_id -q
    with patch('scripts.agent_groups.getopt', return_value=([('-a', 'None'), ('-g', 'group1'), ('-q', 'None')], None)):
        agent_groups.main()
        create_group_mock.assert_called_once_with('group1', True)

    # -a
    with patch('scripts.agent_groups.getopt', return_value=([('-a', 'None')], None)):
        agent_groups.main()
        invalid_option_mock.assert_called_once_with("Missing agent ID or group.")
        invalid_option_mock.reset_mock()

    # -s
    with patch('scripts.agent_groups.getopt', return_value=([('-s', 'None')], None)):
        agent_groups.main()
        invalid_option_mock.assert_called_once_with("Missing agent ID.")
        invalid_option_mock.reset_mock()

    # -s -i agent_id
    with patch('scripts.agent_groups.getopt', return_value=([('-s', 'None'), ('-i', '002')], None)):
        agent_groups.main()
        show_group_mock.assert_called_once_with("002")

    # -S
    with patch('scripts.agent_groups.getopt', return_value=([('-S', 'None')], None)):
        agent_groups.main()
        invalid_option_mock.assert_called_once_with("Missing agent ID.")
        invalid_option_mock.reset_mock()

    # -S -i agent_id
    with patch('scripts.agent_groups.getopt', return_value=([('-S', 'None'), ('-i', '003')], None)):
        agent_groups.main()
        show_synced_agent_mock.assert_called_once_with("003")

    # -r -i agent_id
    with patch('scripts.agent_groups.getopt', return_value=([('-r', 'None'), ('-i', '004')], None)):
        agent_groups.main()
        unset_group_mock.assert_called_once_with('004', None, False)
        unset_group_mock.reset_mock()

    # -r -i agent_id -g group_id
    with patch('scripts.agent_groups.getopt', return_value=([('-r', 'None'), ('-i', '004'), ('-g', 'group1')], None)):
        agent_groups.main()
        unset_group_mock.assert_called_once_with('004', 'group1', False)
        unset_group_mock.reset_mock()

    # -r -i agent_id -q
    with patch('scripts.agent_groups.getopt', return_value=([('-r', 'None'), ('-i', '004'), ('-q', 'None')], None)):
        agent_groups.main()
        unset_group_mock.assert_called_once_with('004', None, True)

    # -r -g group_id
    with patch('scripts.agent_groups.getopt', return_value=([('-r', 'None'), ('-g', 'group2')], None)):
        agent_groups.main()
        remove_group_mock.assert_called_once_with('group2', False)
        remove_group_mock.reset_mock()

    # -r -g group_id -q
    with patch('scripts.agent_groups.getopt', return_value=([('-r', 'None'), ('-g', 'group2'), ('-q', 'None')], None)):
        agent_groups.main()
        remove_group_mock.assert_called_once_with('group2', True)

    # -r
    with patch('scripts.agent_groups.getopt', return_value=([('-r', 'None')], None)):
        agent_groups.main()
        invalid_option_mock.assert_called_once_with("Missing agent ID or group.")
        invalid_option_mock.reset_mock()

    # -X (missing parameter)
    with patch('scripts.agent_groups.getopt', return_value=([('-X', 'None')], None)):
        agent_groups.main()
        invalid_option_mock.assert_called_with("Bad argument combination.")


@patch('builtins.print')
def test_setup(print_mock):
    """Test the setup function."""
    # Change to debug mode
    agent_groups.debug = True
    with patch('scripts.agent_groups.read_config',
               return_value={'nodes': ['master'], 'node_type': 'worker', 'disabled': False}) as read_config_mock:
        with pytest.raises(WazuhError, match=".* 3019 .*"):
            agent_groups.setup()
        read_config_mock.assert_called_once()
        print_mock.assert_called_once_with(
            'Error 3019: Wazuh is running in cluster mode: agent_groups is not available in worker nodes. '
            'Please, try again in the master node: master')
        print_mock.reset_mock()

    with patch('scripts.agent_groups.read_config',
               return_value={'nodes': ['master'], 'node_type': 'master', 'disabled': False}) as read_config_mock:
        with patch('scripts.agent_groups.main') as main_mock:
            agent_groups.setup()
            read_config_mock.assert_called_once()
            main_mock.assert_called_once()
            read_config_mock.reset_mock()
            main_mock.reset_mock()

        class ExceptionMock(Exception):
            def __init__(self, msg='Test exception', *args, **kwargs):
                super().__init__(msg, *args, **kwargs)

        with patch('scripts.agent_groups.main', side_effect=ExceptionMock) as main_mock:
            with pytest.raises(ExceptionMock):
                agent_groups.setup()
            read_config_mock.assert_called_once()
            main_mock.assert_called_once()
            print_mock.assert_called_once_with(f"Internal error: Test exception")
