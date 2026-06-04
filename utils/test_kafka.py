"""
test_kafka.py — run on host (outside Docker) to verify Kafka broker is reachable.

Usage:
    pip install kafka-python
    python test_kafka.py
"""
from kafka import KafkaProducer, KafkaAdminClient
from kafka.admin import NewTopic
from kafka.errors import TopicAlreadyExistsError
import json, time

BROKER = "localhost:9094"   # host-side port mapping

def test_connection():
    print("Testing Kafka connection...")
    try:
        admin = KafkaAdminClient(bootstrap_servers=BROKER)
        topics = admin.list_topics()
        print(f"[+] Connected. Existing topics: {topics or '(none yet)'}")
        admin.close()
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        return False
    return True

def test_produce_consume():
    print("Testing produce/consume roundtrip...")
    topic = "test_topic"

    # Produce
    producer = KafkaProducer(
        bootstrap_servers=BROKER,
        value_serializer=lambda x: json.dumps(x).encode("utf-8")
    )
    producer.send(topic, value={"hello": "world", "ts": time.time()})
    producer.flush()
    print("[+] Message produced to test_topic")

    # Consume (one message, timeout after 5s)
    from kafka import KafkaConsumer
    consumer = KafkaConsumer(
        topic,
        bootstrap_servers=BROKER,
        auto_offset_reset="earliest",
        consumer_timeout_ms=5000,
        value_deserializer=lambda x: json.loads(x.decode("utf-8"))
    )
    for msg in consumer:
        print(f"[+] Message consumed: {msg.value}")
        break
    else:
        print("[-] No message received within 5 seconds")
    consumer.close()

if __name__ == "__main__":
    if test_connection():
        test_produce_consume()
    print("\nDone. If both checks passed, Kafka is ready.")