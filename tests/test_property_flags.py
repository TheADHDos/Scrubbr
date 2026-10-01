import socket

import pytest
from bs4 import BeautifulSoup
from fastapi.testclient import TestClient

from app import db, main, property_flags as flags, removal_history


@pytest.mark.parametrize('name,url,domain,impact', [
    ('Radaris', '', 'radaris.com', 'transferred'),
    ('Radaris.com', '', 'radaris.com', 'transferred'),
    ('Radaris', 'https://www.radaris.com/example', 'radaris.com', 'transferred'),
    ('Radaris', 'https://radaris.net/example', 'radaris.net', 'related'),
    ('Radaris', 'https://radaris.co.uk/example', 'radaris.co.uk', 'related'),
    ('Homemetry', '', 'homemetry.com', 'related'),
    ('Synthetic site', 'https://radaris.com.evil.example/', None, None),
    ('Radaris', 'https://unlisted.example/', None, None),
    ('Radaris', 'https://unknown.radaris.com/', None, None),
    ('Radaris', 'file:///tmp/example', None, None),
    ('Radaris affiliate', '', None, None),
])
def test_exact_matching_does_not_propagate_between_domains(name, url, domain, impact):
    flag = flags.flag_for(name, url)
    assert ((flag['domain'], flag['impact']) if flag else (None, None)) == (domain, impact)


def test_curated_provenance_and_filters():
    transferred = flags.filtered('transferred')
    assert len(transferred) == 15
    assert len({e['domain'] for e in flags.ENTRIES}) == len(flags.ENTRIES)
    assert {e['judgment_date'] for e in transferred} == {'2026-06-12', '2026-08-27'}
    assert all(e['source_url'] and e['reviewed_date'] == '2026-10-01' and e['case'] for e in transferred)
    assert all(not e['judgment_date'] and not e['case'] for e in flags.filtered('related'))
    assert flags.filtered('transferred', ' RADARIS ') == [flags.flag_for('Radaris')]
    assert flags.filtered('related', 'radaris.net')[0]['domain'] == 'radaris.net'


@pytest.fixture
def client(tmp_path, monkeypatch):
    path = tmp_path/'synthetic.db'
    def conn():
        c = db.connect(path); db.init_db(c); return c
    monkeypatch.setattr(main, 'get_conn', conn)
    def fail(*a, **kw): pytest.fail('Unexpected outbound/automation operation')
    monkeypatch.setattr(socket.socket, 'connect', fail)
    monkeypatch.setattr(socket, 'create_connection', fail)
    monkeypatch.setattr(main.scan_service, 'scan_and_persist', fail)
    monkeypatch.setattr(main.send_service, 'send_and_persist', fail)
    monkeypatch.setattr(main.inbox, 'poll', fail)
    c=conn()
    for name,url in [('Radaris',''), ('Radaris','https://radaris.net/synthetic'), ('Synthetic unrelated site','')]:
        values, errors = removal_history.validate({'site_name':name, 'listing_url':url,
            'status':'requested', 'notes':'Synthetic only', 'recheck_date':'2026-10-03'})
        assert not errors
        db.save_removal_record(c,values)
    c.close()
    with TestClient(main.app,base_url='http://127.0.0.1:3001') as browser:
        yield browser


def test_public_page_is_profile_free_and_never_opens_database(client, monkeypatch):
    monkeypatch.setattr(main, 'get_conn', lambda: pytest.fail('Public page opened the database'))
    soup=BeautifulSoup(client.get('/properties?impact=transferred').text,'html.parser')
    assert len(soup.select('section')) == 15
    assert 'Related property — impact unconfirmed' not in soup.select_one('main').get_text().split('Showing')[1]
    assert all(set(a['rel']) >= {'noopener','noreferrer'} for a in soup.select('a[target="_blank"]'))
    assert 'does not establish that your data was deleted' in soup.get_text()
    assert 'No properties match' in client.get('/properties?q=unknown-synthetic').text
    assert '&lt;script&gt;' in client.get('/properties?q=%3Cscript%3E').text
    assert len(BeautifulSoup(client.get('/properties?impact=invalid').text,'html.parser').select('section')) == len(flags.ENTRIES)


def test_tracker_filters_and_form_flags_do_not_change_saved_data(client):
    c=main.get_conn()
    before=db.removal_records(c)
    history=[db.removal_record_history(c,r['id']) for r in before]
    c.close()

    for impact, expected in [('transferred','radaris.com'), ('related','radaris.net')]:
        page=client.get('/history?impact='+impact)
        assert page.status_code == 200 and 'Showing 1 of 3 records' in page.text
        soup=BeautifulSoup(page.text,'html.parser')
        assert soup.select_one('a[href="/properties#'+expected+'"]')
    assert 'Showing 0 of 3 records' in client.get('/history?impact=transferred&status=confirmed').text
    assert 'Showing 3 of 3 records' in client.get('/history?impact=invalid').text
    assert '/properties#radaris.com' in client.get('/history/1/edit').text
    assert '/properties#radaris.net' in client.get('/history/2/edit').text
    c=main.get_conn()
    assert db.removal_records(c) == before
    assert [db.removal_record_history(c,r['id']) for r in before] == history
    assert not db.all_profiles(c)
    assert c.execute('SELECT count(*) FROM requests').fetchone()[0] == 0
    c.close()


def test_broker_directory_displays_domain_flag(client):
    c=main.get_conn()
    db.create_profile(c, {'name':'Synthetic browser profile', 'full_name':'Synthetic Test',
        'aliases':'', 'emails':'', 'phones':'', 'addresses':'', 'date_of_birth':'', 'state':''})
    db.upsert_broker(c, {'name':'Radaris', 'category':'people-search', 'website':'https://radaris.com/'})
    db.upsert_broker(c, {'name':'Synthetic related domain', 'category':'people-search', 'website':'https://radaris.net/'})
    c.commit(); c.close()
    page=client.get('/brokers')
    assert page.status_code == 200
    soup=BeautifulSoup(page.text,'html.parser')
    assert soup.select_one('a[href="/properties#radaris.com"]')
    assert soup.select_one('a[href="/properties#radaris.net"]')
