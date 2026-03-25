import traceback
try:
    from report_generator import generate_pdf_report
    from collections import Counter
    b = {
        'avg_packet_size': 512.0,
        'total_bytes': 2048,
        'active_ports': Counter({80: 10}),
        'protocol_dist': Counter({'TCP': 5}),
        'peak_request_rate': 2
    }
    stats = {
        'total_packets': 10,
        'anomaly_count': 1,
        'blocked_count': 0,
        'safe_level': 99,
        'anomaly_rate': 10.0
    }
    model = {
        'model_type': 'XGBoost',
        'accuracy': 0.9842,
        'features': ['pkt_len']
    }
    alerts = [{
        'source': '1.1.1.1',
        'attack_type': 'Bot',
        'reason': 'Test Reason',
        'confidence': 80,
        'severity': 'Low',
        'action': 'Flagged',
        'is_anomaly': True
    }]
    generate_pdf_report(alerts, stats, model, behavior_stats=b)
    print('SUCCESS')
except Exception:
    traceback.print_exc()
