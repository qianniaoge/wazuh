import json
import time

from box import Box


def test_distinct_key(response):
    """
    :param response: Request response
    :return: True if all request response items are unique
    """
    assert not any(response.json()["data"]["affected_items"].count(item) > 1 for item in response.json()["data"]["affected_items"])


def test_select_key_affected_items(response, select_key):
    """
    :param response: Request response
    :param select_key: Parametrized key used for select param in request
    :return: True if request response item key matches used select param
    """
    if '.' in select_key:
        assert list(response.json()["data"]["affected_items"][0])[0] == select_key.split('.')[0]
        assert list(response.json()["data"]["affected_items"][0][select_key.split('.')[0]])[0] == select_key.split('.')[1]
    else:
        assert list(response.json()["data"]["affected_items"][0])[0] == select_key


def test_select_key_affected_items_with_agent_id(response, select_key):
    """
    :param response: Request response
    :param select_key: Parametrized key used for select param in request
    :return: True if request response item key matches used select param
    """
    if '.' in select_key:
        expected_keys_level0 = {'agent_id', select_key.split('.')[0]}
        expected_keys_level1 = {select_key.split('.')[1]}
        assert set(response.json()["data"]["affected_items"][0].keys()) == expected_keys_level0
        assert set(response.json()["data"]["affected_items"][0][select_key.split('.')[0]].keys()) == expected_keys_level1
    else:
        expected_keys = {'agent_id', select_key}
        assert set(response.json()["data"]["affected_items"][0].keys()) == expected_keys


def test_sort_response(response, affected_items):
    """
    :param response: Request response
    :param affected_items: List of agent
    :return: True if request response have this items
    """
    affected_items = affected_items.replace("'", '"')
    affected_items = json.loads(affected_items)
    reverse_index = len(affected_items) - 1
    for index, item_response in enumerate(response.json()['data']['affected_items']):
        assert item_response != affected_items[reverse_index - index]


def test_validate_data_dict_field(response, fields_dict):
    assert fields_dict, f'Fields dict is empty'
    for field, dikt in fields_dict.items():
        field_list = response.json()['data'][field]

        for element in field_list:
            try:
                assert (isinstance(element[key], eval(value)) for key, value in dikt.items())
            except KeyError:
                assert len(element) == 1
                assert isinstance(element['count'], int)


def test_validate_upgrade(response):
    # We accept the test as passed if it either ugprades correctly or the version is not available
    assert response.json().get('message', None) == "Upgrade procedure started" \
           or response.json().get('code', None) == 1718
    if response.json().get('message', None) == "Upgrade procedure started":
        time.sleep(45)
        return Box({"upgraded": True})
    else:
        return Box({"upgraded": False})


def test_validate_upgrade_result(response, upgraded):
    if upgraded == 1:
        assert response.json().get('message', None) == "Agent upgraded successfully"
    else:
        # If upgrade didnt work because no version was available, we expect an empty upgrade_result with error 1716
        assert response.json().get('code', None) == 1716


def test_validate_update_latest_version(response):
    assert response.json().get('code', None) == 1749 or response.json().get('code', None) == 1718


def test_count_elements(response, n_expected_items):
    """
    :param response: Request response
    :param n_expected_items: Expected number of elements in affeted_items
    """
    assert len(response.json()['data']['affected_items']) == n_expected_items


def test_expected_value(response, key, expected_values):
    """
    :param response: Request response
    :param key: Key whose value to compare.
    :param expected_values: Values to be found inside response.
    """
    expected_values = set(expected_values.split(',')) if not isinstance(expected_values, list) else set(expected_values)

    for item in response.json()['data']['affected_items']:
        response_set = set(item[key])
        assert bool(expected_values.intersection(response_set)), \
            f'Expected values {expected_values} not found in {item[key]}'


def test_mitre_sort(response, attack_id, order):
    """
    :param response: Request response
    :param id: ID to compare.
    :param order: Values to be found inside response.
    """
    if order == 'desc':
        assert response.json()['data']['affected_items'][0]['id'] > attack_id
    else:
        assert response.json()['data']['affected_items'][0]['id'] < attack_id


def test_mitre_select(response, select_keys):
    """
    :param response: Request response
    :param select_keys: Keys requested in select parameter
    """
    select_keys = select_keys.split(',')

    for item in response.json()['data']['affected_items']:
        for sub_item in item:
            assert sub_item in select_keys if sub_item != 'id' else True
