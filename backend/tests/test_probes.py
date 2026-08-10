from correlation import active_probes, tls_check


# --- SNMP packet builder ---------------------------------------------------

def test_snmp_request_is_valid_sequence():
    pkt = active_probes.snmp_get_request("public")
    assert pkt[0] == 0x30                 # top-level SEQUENCE
    assert pkt[1] == len(pkt) - 2         # declared length matches actual body
    assert b"public" in pkt               # community string embedded
    assert bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]) in pkt  # sysDescr OID


def test_snmp_request_varies_by_community():
    assert b"private" in active_probes.snmp_get_request("private")


# --- MQTT packet builder ---------------------------------------------------

def test_mqtt_connect_packet_shape():
    pkt = active_probes.mqtt_connect_packet()
    assert pkt[0] == 0x10                  # CONNECT control packet type
    assert b"MQTT" in pkt                  # protocol name
    assert pkt[1] == len(pkt) - 2          # single-byte remaining length


def test_mqtt_remaining_length_encoding():
    assert active_probes._mqtt_remaining_length(0) == b"\x00"
    assert active_probes._mqtt_remaining_length(127) == b"\x7f"
    assert active_probes._mqtt_remaining_length(128) == b"\x80\x01"


# --- TLS port classification ----------------------------------------------

def test_is_tls_port():
    assert tls_check.is_tls_port(443, None)
    assert tls_check.is_tls_port(8443, None)
    assert tls_check.is_tls_port(8080, "https")
    assert not tls_check.is_tls_port(80, "http")
    assert not tls_check.is_tls_port(23, "telnet")


# --- Unauthenticated firmware-update endpoint -------------------------------

def test_firmware_endpoint_found(monkeypatch):
    class Resp:
        def __init__(self, code):
            self.status_code = code

    def fake_get(url, **kwargs):
        # Only the known upgrade path answers 200; everything else 404s.
        return Resp(200) if url.endswith("/upgrade.cgi") else Resp(404)

    monkeypatch.setattr(active_probes.requests, "get", fake_get)
    finding = active_probes.unauthenticated_firmware_endpoint("1.2.3.4", 80, "http")
    assert finding is not None
    assert finding["finding_type"] == "insecure_update_endpoint"
    assert "/upgrade.cgi" in finding["description"]


def test_firmware_endpoint_none_when_all_protected(monkeypatch):
    class Resp:
        status_code = 401

    monkeypatch.setattr(active_probes.requests, "get", lambda url, **kwargs: Resp())
    assert active_probes.unauthenticated_firmware_endpoint("1.2.3.4", 80, "http") is None


def test_firmware_endpoint_fails_closed_on_connection_error(monkeypatch):
    def raise_conn_error(url, **kwargs):
        raise active_probes.requests.RequestException("connection refused")

    monkeypatch.setattr(active_probes.requests, "get", raise_conn_error)
    assert active_probes.unauthenticated_firmware_endpoint("1.2.3.4", 80, "http") is None
