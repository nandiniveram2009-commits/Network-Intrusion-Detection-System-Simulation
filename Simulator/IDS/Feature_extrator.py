import ipaddress

def extract_network_features(flow_data):
    """
    Extracts advanced statistical security features from raw network flow dictionaries.
    Includes robust input validation and division-by-zero protection.
    """
    try:
        # Validate IP addresses
        ipaddress.ip_address(flow_data.get("source_ip", "0.0.0.0"))
        ipaddress.ip_address(flow_data.get("destination_ip", "0.0.0.0"))
    except ValueError:
        raise ValueError("Malformed source or destination IP address.")

    ports = [flow_data.get("source_port", 0), flow_data.get("destination_port", 0)]
    for p in ports:
        if not (0 <= p <= 65535):
            raise ValueError(f"Invalid port number: {p}")

    packet_count = max(1, float(flow_data.get("packet_count", 1)))
    byte_count = max(0.0, float(flow_data.get("byte_count", 0.0)))
    duration = max(0.01, float(flow_data.get("duration_seconds", 0.1)))
    
    connection_count = max(1.0, float(flow_data.get("connection_count", 1.0)))
    failed_connection_count = max(0.0, float(flow_data.get("failed_connection_count", 0.0)))
    syn_count = max(0.0, float(flow_data.get("syn_count", 0.0)))
    rst_count = max(0.0, float(flow_data.get("rst_count", 0.0)))

    # Derived security features
    bytes_per_second = round(byte_count / duration, 2)
    packets_per_second = round(packet_count / duration, 2)
    average_packet_size = round(byte_count / packet_count, 2)
    failure_ratio = round(failed_connection_count / connection_count, 4)
    syn_ratio = round(syn_count / packet_count, 4)
    connection_rate = round(connection_count / duration, 2)

    features = {
        "packet_count": int(packet_count),
        "byte_count": int(byte_count),
        "duration": float(duration),
        "bytes_per_second": bytes_per_second,
        "packets_per_second": packets_per_second,
        "average_packet_size": average_packet_size,
        "connection_count": int(connection_count),
        "failed_connection_count": int(failed_connection_count),
        "failure_ratio": failure_ratio,
        "syn_count": int(syn_count),
        "rst_count": int(rst_count),
        "syn_ratio": syn_ratio,
        "connection_rate": connection_rate
    }
    
    return features
