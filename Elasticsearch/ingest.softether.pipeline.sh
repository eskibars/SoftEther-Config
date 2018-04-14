curl -XPUT "https://YOUR_SERVER/_ingest/pipeline/softether" -H 'Content-Type: application/json' -d'
{
  "description": "Softether Packet Log",
  "processors": [
    {
      "split": {
        "field": "message",
        "separator": ","
      }
    },
    {
      "script": {
        "lang": "painless",
        "source": "ctx.date = (ctx.message[0] + \" \" + ctx.message[1]);\n          ctx.src_session = ctx.message[2];\n          ctx.dst_session = ctx.message[3];\n          ctx.src_mac = ctx.message[4];\n          ctx.dst_mac = ctx.message[5];\n          ctx.mac_proto = ctx.message[6];\n          ctx.packet_size = ctx.message[7];\n          ctx.packet_type = ctx.message[8];\n          ctx.tcp_flags = ctx.message[9];\n          ctx.src_ip = ctx.message[10];\n          ctx.src_port = ctx.message[11];\n          ctx.dst_ip = ctx.message[12];\n          ctx.dst_port = ctx.message[13];\n          ctx.tcp_seq_no = ctx.message[14];\n          ctx.tcp_ack_no = ctx.message[15];\n          ctx.packet_data = ctx.message[16];\n          ctx.packet_flags = ctx.message[17];\n          ctx.phys_src_ip = ctx.message[18];\n          ctx.phys_dst_ip = ctx.message[19]"
      }
    },
    {
      "script": {
        "lang": "painless",
        "source": "          if (ctx.src_session == \"SID-SECURENAT-1\" && ctx.dst_session == \"-\" && ctx.src_port == \"echo(7)\") { ctx._index = \"softether-junk\"; ctx._source = null }"
      }
    },
    {
      "script": {
        "lang": "painless",
        "source": "          if (ctx.src_ip == \"-\") { ctx.src_ip = null; }\n          if (ctx.dst_ip == \"-\") { ctx.dst_ip = null; }\n          if (ctx.phys_src_ip == \"-\") { ctx.phys_src_ip = null; }\n          if (ctx.phys_dst_ip == \"-\") { ctx.phys_dst_ip = null; }\n          if (ctx.src_mac == \"-\") { ctx.src_mac = null; }\n          if (ctx.dst_mac == \"-\") { ctx.dst_mac = null; }"
      }
    },
    {
      "split": {
        "field": "tcp_flags",
        "separator": "\\+"
      }
    },
    {
      "kv": {
        "field": "packet_data",
        "field_split": " ",
        "value_split": "=",
        "target_field": "packet_data_flags",
        "ignore_failure": true
      }
    },
    {
      "remove": {
        "field": "message"
      }
    },
    {
      "grok": {
        "field": "src_port",
        "patterns": [
          "%{NUMBER:src_port_num}"
        ],
        "ignore_failure": true
      }
    },
    {
      "grok": {
        "field": "dst_port",
        "patterns": [
          "%{NUMBER:dst_port_num}"
        ],
        "ignore_failure": true
      }
    },
    {
      "grok": {
        "field": "src_session",
        "patterns": [
          "SID-%{USERNAME:username}-\\[%{DATA:vpn_type}\\]-%{NONNEGINT:session_number}"
        ],
        "ignore_failure": true
      }
    },
    {
      "grok": {
        "field": "dst_session",
        "patterns": [
          "SID-%{USERNAME:username}-\\[%{DATA:vpn_type}\\]-%{NONNEGINT:session_number}"
        ],
        "ignore_failure": true
      }
    },
    {
      "grok": {
        "field": "packet_data_flags.HttpUrl",
        "patterns": [
          "%{URIPROTO:packet_data_flags.HttpProtocol}://%{URIHOST:packet_data_flags.HttpHost}%{URIPATH:packet_data_flags.HttpPath}%{URIPARAM:packet_data_flags.HttpParam}",
          "%{URIPROTO:packet_data_flags.HttpProtocol}://%{URIHOST:packet_data_flags.HttpHost}%{URIPATH:packet_data_flags.HttpPath}",
          "%{URIPROTO:packet_data_flags.HttpProtocol}://%{URIHOST:packet_data_flags.HttpHost}"
        ],
        "ignore_failure": true
      }
    },
    {
      "user_agent": {
        "field": "packet_data_flags.HttpUserAgent",
        "target_field": "packet_data_flags.user_agent",
        "ignore_failure": true
      }
    },
    {
      "date": {
        "field": "date",
        "formats": [
          "yyyy-MM-dd HH:mm:ss.SSS"
        ],
        "target_field": "date"
      }
    },
    {
      "geoip": {
        "field": "dst_ip",
        "target_field": "dst_geo",
        "ignore_failure": true
      }
    },
    {
      "geoip": {
        "field": "src_ip",
        "target_field": "src_geo",
        "ignore_failure": true
      }
    },
    {
      "geoip": {
        "field": "phys_src_ip",
        "target_field": "phys_src_geo",
        "ignore_failure": true
      }
    },
    {
      "geoip": {
        "field": "phys_dst_ip",
        "target_field": "phys_dst_geo",
        "ignore_failure": true
      }
    }
  ]
}'
