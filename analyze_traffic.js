const { Client } = require('@elastic/elasticsearch');
const moment = require('moment');

// ElasticSearch 連接
const esClient = new Client({
  node: 'http://localhost:9200'
});

async function analyzeTraffic() {
  console.log('=== 網路流量分析報告 ===\n');
  console.log(`分析時間: ${moment().format('YYYY-MM-DD HH:mm:ss')}`);
  console.log(`分析區間: 過去1小時\n`);

  const oneHourAgo = moment().subtract(1, 'hour').valueOf();
  const now = moment().valueOf();
  const indexPattern = `radar_flow_collector-${moment().format('YYYY.MM.DD')}`;

  try {
    // 1. 查詢總流量統計
    console.log('--- 1. 流量總覽 ---');
    const totalStats = await esClient.search({
      index: indexPattern,
      body: {
        query: {
          range: {
            FLOW_START_MILLISECONDS: {
              gte: oneHourAgo,
              lte: now
            }
          }
        },
        aggs: {
          total_bytes: { sum: { field: 'IN_BYTES' } },
          total_packets: { sum: { field: 'IN_PKTS' } },
          total_flows: { value_count: { field: 'IPV4_SRC_ADDR' } }
        },
        size: 0
      }
    });

    const totalBytes = totalStats.aggregations.total_bytes.value;
    const totalPackets = totalStats.aggregations.total_packets.value;
    const totalFlows = totalStats.aggregations.total_flows.value;

    console.log(`總流量: ${(totalBytes / 1024 / 1024 / 1024).toFixed(2)} GB`);
    console.log(`總封包數: ${totalPackets.toLocaleString()}`);
    console.log(`總連線數: ${totalFlows.toLocaleString()}\n`);

    // 2. Top 10 流量來源 IP
    console.log('--- 2. Top 10 流量來源 IP ---');
    const topSrcIPs = await esClient.search({
      index: indexPattern,
      body: {
        query: {
          range: {
            FLOW_START_MILLISECONDS: {
              gte: oneHourAgo,
              lte: now
            }
          }
        },
        aggs: {
          top_src_ips: {
            terms: {
              field: 'IPV4_SRC_ADDR',
              size: 10,
              order: { total_bytes: 'desc' }
            },
            aggs: {
              total_bytes: { sum: { field: 'IN_BYTES' } },
              total_packets: { sum: { field: 'IN_PKTS' } },
              total_flows: { value_count: { field: 'IPV4_SRC_ADDR' } }
            }
          }
        },
        size: 0
      }
    });

    topSrcIPs.aggregations.top_src_ips.buckets.forEach((bucket, index) => {
      const bytes = bucket.total_bytes.value;
      const packets = bucket.total_packets.value;
      const flows = bucket.total_flows.value;
      console.log(`${index + 1}. ${bucket.key}`);
      console.log(`   流量: ${(bytes / 1024 / 1024).toFixed(2)} MB`);
      console.log(`   封包數: ${packets.toLocaleString()}`);
      console.log(`   連線數: ${flows.toLocaleString()}`);
    });

    // 3. Top 10 流量目的 IP
    console.log('\n--- 3. Top 10 流量目的 IP ---');
    const topDstIPs = await esClient.search({
      index: indexPattern,
      body: {
        query: {
          range: {
            FLOW_START_MILLISECONDS: {
              gte: oneHourAgo,
              lte: now
            }
          }
        },
        aggs: {
          top_dst_ips: {
            terms: {
              field: 'IPV4_DST_ADDR',
              size: 10,
              order: { total_bytes: 'desc' }
            },
            aggs: {
              total_bytes: { sum: { field: 'IN_BYTES' } },
              total_packets: { sum: { field: 'IN_PKTS' } },
              total_flows: { value_count: { field: 'IPV4_DST_ADDR' } }
            }
          }
        },
        size: 0
      }
    });

    topDstIPs.aggregations.top_dst_ips.buckets.forEach((bucket, index) => {
      const bytes = bucket.total_bytes.value;
      const packets = bucket.total_packets.value;
      const flows = bucket.total_flows.value;
      console.log(`${index + 1}. ${bucket.key}`);
      console.log(`   流量: ${(bytes / 1024 / 1024).toFixed(2)} MB`);
      console.log(`   封包數: ${packets.toLocaleString()}`);
      console.log(`   連線數: ${flows.toLocaleString()}`);
    });

    // 4. 異常檢測: 高流量連線 (超過100MB的單一連線)
    console.log('\n--- 4. 異常高流量連線 (單一連線 > 100MB) ---');
    const highVolumeFlows = await esClient.search({
      index: indexPattern,
      body: {
        query: {
          bool: {
            must: [
              {
                range: {
                  FLOW_START_MILLISECONDS: {
                    gte: oneHourAgo,
                    lte: now
                  }
                }
              },
              {
                range: {
                  IN_BYTES: {
                    gte: 100 * 1024 * 1024  // 100MB
                  }
                }
              }
            ]
          }
        },
        sort: [
          { IN_BYTES: 'desc' }
        ],
        size: 20,
        _source: ['IPV4_SRC_ADDR', 'IPV4_DST_ADDR', 'L4_DST_PORT', 'PROTOCOL', 'IN_BYTES', 'IN_PKTS', 'FLOW_START_MILLISECONDS']
      }
    });

    if (highVolumeFlows.hits.hits.length > 0) {
      console.log(`⚠️  發現 ${highVolumeFlows.hits.hits.length} 個異常高流量連線:`);
      highVolumeFlows.hits.hits.forEach((hit, index) => {
        const src = hit._source;
        const startTime = moment(src.FLOW_START_MILLISECONDS).format('HH:mm:ss');
        console.log(`\n${index + 1}. [${startTime}]`);
        console.log(`   來源: ${src.IPV4_SRC_ADDR} → 目的: ${src.IPV4_DST_ADDR}:${src.L4_DST_PORT}`);
        console.log(`   協定: ${src.PROTOCOL}`);
        console.log(`   流量: ${(src.IN_BYTES / 1024 / 1024).toFixed(2)} MB`);
        console.log(`   封包數: ${src.IN_PKTS.toLocaleString()}`);
      });
    } else {
      console.log('✓ 未發現異常高流量連線');
    }

    // 5. 異常檢測: 高連線數 IP (單一IP超過1000個連線)
    console.log('\n--- 5. 異常高連線數 IP (單一IP > 1000 連線) ---');
    const highConnectionIPs = await esClient.search({
      index: indexPattern,
      body: {
        query: {
          range: {
            FLOW_START_MILLISECONDS: {
              gte: oneHourAgo,
              lte: now
            }
          }
        },
        aggs: {
          src_ips: {
            terms: {
              field: 'IPV4_SRC_ADDR',
              size: 100,
              min_doc_count: 1000
            },
            aggs: {
              total_bytes: { sum: { field: 'IN_BYTES' } },
              unique_destinations: {
                cardinality: { field: 'IPV4_DST_ADDR' }
              }
            }
          }
        },
        size: 0
      }
    });

    if (highConnectionIPs.aggregations.src_ips.buckets.length > 0) {
      console.log(`⚠️  發現 ${highConnectionIPs.aggregations.src_ips.buckets.length} 個異常高連線數 IP:`);
      highConnectionIPs.aggregations.src_ips.buckets.forEach((bucket, index) => {
        console.log(`\n${index + 1}. ${bucket.key}`);
        console.log(`   連線數: ${bucket.doc_count.toLocaleString()}`);
        console.log(`   流量: ${(bucket.total_bytes.value / 1024 / 1024).toFixed(2)} MB`);
        console.log(`   連線到不同目的地數量: ${bucket.unique_destinations.value}`);
      });
    } else {
      console.log('✓ 未發現異常高連線數 IP');
    }

    // 6. 異常檢測: 可疑掃描行為 (連線到大量不同目的地但流量小)
    console.log('\n--- 6. 可疑掃描行為偵測 ---');
    const scanningIPs = await esClient.search({
      index: indexPattern,
      body: {
        query: {
          range: {
            FLOW_START_MILLISECONDS: {
              gte: oneHourAgo,
              lte: now
            }
          }
        },
        aggs: {
          src_ips: {
            terms: {
              field: 'IPV4_SRC_ADDR',
              size: 100,
              min_doc_count: 100
            },
            aggs: {
              total_bytes: { sum: { field: 'IN_BYTES' } },
              unique_destinations: {
                cardinality: { field: 'IPV4_DST_ADDR' }
              },
              avg_bytes_per_flow: {
                avg: { field: 'IN_BYTES' }
              }
            }
          }
        },
        size: 0
      }
    });

    const suspiciousScanning = scanningIPs.aggregations.src_ips.buckets.filter(bucket => {
      const avgBytesPerFlow = bucket.avg_bytes_per_flow.value;
      const uniqueDests = bucket.unique_destinations.value;
      // 平均每個連線流量小於10KB 且連線到超過50個不同目的地
      return avgBytesPerFlow < 10000 && uniqueDests > 50;
    });

    if (suspiciousScanning.length > 0) {
      console.log(`⚠️  發現 ${suspiciousScanning.length} 個可疑掃描 IP:`);
      suspiciousScanning.forEach((bucket, index) => {
        console.log(`\n${index + 1}. ${bucket.key}`);
        console.log(`   連線數: ${bucket.doc_count.toLocaleString()}`);
        console.log(`   連線到不同目的地: ${bucket.unique_destinations.value}`);
        console.log(`   平均每連線流量: ${(bucket.avg_bytes_per_flow.value / 1024).toFixed(2)} KB`);
        console.log(`   總流量: ${(bucket.total_bytes.value / 1024 / 1024).toFixed(2)} MB`);
      });
    } else {
      console.log('✓ 未發現可疑掃描行為');
    }

    // 7. 協定分布
    console.log('\n--- 7. 流量協定分布 ---');
    const protocolDist = await esClient.search({
      index: indexPattern,
      body: {
        query: {
          range: {
            FLOW_START_MILLISECONDS: {
              gte: oneHourAgo,
              lte: now
            }
          }
        },
        aggs: {
          protocols: {
            terms: {
              field: 'PROTOCOL',
              size: 10
            },
            aggs: {
              total_bytes: { sum: { field: 'IN_BYTES' } }
            }
          }
        },
        size: 0
      }
    });

    protocolDist.aggregations.protocols.buckets.forEach((bucket, index) => {
      const bytes = bucket.total_bytes.value;
      const percentage = ((bytes / totalBytes) * 100).toFixed(2);
      console.log(`${index + 1}. 協定 ${bucket.key}: ${(bytes / 1024 / 1024).toFixed(2)} MB (${percentage}%)`);
    });

    console.log('\n=== 分析完成 ===');

  } catch (error) {
    console.error('查詢錯誤:', error.message);
    if (error.meta) {
      console.error('詳細資訊:', JSON.stringify(error.meta.body, null, 2));
    }
  }
}

analyzeTraffic();
