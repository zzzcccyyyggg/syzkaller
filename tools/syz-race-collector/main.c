// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// ============================================
// syz-race-collector: 独立的 Race Pair 收集工具
// 
// 用于在运行任意程序（如 iozone、原版 syzkaller 等）时
// 被动收集 race pair 信息，以便与 DDRD-syzkaller 进行对比。
//
// 用法示例:
//   sudo ./syz-race-collector -o races.csv &
//   iozone -a -i 0 -i 1
//   kill %1
//
// 或者:
//   sudo ./syz-race-collector --duration=3600 --interval=500 -o races.json --format=json
// ============================================

#define _DEFAULT_SOURCE  // for usleep
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <errno.h>

#include "config.h"
#include "collector.h"
#include "analyzer.h"
#include "reporter.h"

// ============================================
// 全局状态
// ============================================
static volatile bool g_running = true;

// ============================================
// 信号处理
// ============================================
static void signal_handler(int sig) {
    (void)sig;
    g_running = false;
}

// ============================================
// 帮助信息
// ============================================
static void print_usage(const char* prog) {
    fprintf(stderr, 
        "syz-race-collector - Standalone race pair collection tool\n"
        "\n"
        "Usage: %s [options]\n"
        "\n"
        "Sampling Options:\n"
        "  -i, --interval <ms>       Sampling interval in milliseconds (default: 1000)\n"
        "  -d, --duration <sec>      Run duration in seconds, 0 = until Ctrl+C (default: 0)\n"
        "\n"
        "Detection Thresholds:\n"
        "  --race-threshold <ns>     Time threshold for race pair detection in nanoseconds\n"
        "                            (default: 4270000, ~4.27ms)\n"
        "  --uaf-threshold <ns>      Time threshold for UAF detection in nanoseconds\n"
        "                            (default: 10000000000, 10s)\n"
        "\n"
        "Buffer Settings:\n"
        "  --trace-buffer <kb>       Trace buffer size per CPU in KB (default: 16384)\n"
        "  --max-records <n>         Maximum access records per sample (default: 65536)\n"
        "  --max-pairs <n>           Maximum race pairs per sample (default: 8192)\n"
        "\n"
        "Output Options:\n"
        "  -o, --output <file>       Output file path (CSV or JSON)\n"
        "  -f, --format <fmt>        Output format: csv or json (default: csv)\n"
        "  -v, --verbose             Verbose output\n"
        "  -q, --quiet               Quiet mode (only show final summary)\n"
        "  --no-realtime             Disable realtime output\n"
        "\n"
        "Analysis Options:\n"
        "  --no-dedup                Disable race signal deduplication\n"
        "  --include-locked          Include pairs protected by common locks\n"
        "  --no-uaf                  Disable UAF pair collection\n"
        "\n"
        "Other:\n"
        "  -h, --help                Show this help message\n"
        "  --version                 Show version\n"
        "\n"
        "Examples:\n"
        "  # Basic usage - collect races while running iozone\n"
        "  sudo %s -o races.csv &\n"
        "  iozone -a -i 0 -i 1\n"
        "  kill %%1\n"
        "\n"
        "  # Run for 1 hour with 500ms sampling interval\n"
        "  sudo %s --duration=3600 --interval=500 -o races.csv\n"
        "\n"
        "  # Use custom race detection threshold (1ms)\n"
        "  sudo %s --race-threshold=1000000 -o races.csv\n"
        "\n"
        "  # JSON output with verbose mode\n"
        "  sudo %s -v -f json -o races.json\n"
        "\n",
        prog, prog, prog, prog, prog);
}

static void print_version(void) {
    fprintf(stderr, "syz-race-collector version 1.0.0\n");
    fprintf(stderr, "Part of DDRD-syzkaller project\n");
}

// ============================================
// 参数解析
// ============================================
static struct option long_options[] = {
    // 采样选项
    {"interval",        required_argument, 0, 'i'},
    {"duration",        required_argument, 0, 'd'},
    
    // 检测阈值
    {"race-threshold",  required_argument, 0, 1001},
    {"uaf-threshold",   required_argument, 0, 1002},
    
    // 缓冲区设置
    {"trace-buffer",    required_argument, 0, 1003},
    {"max-records",     required_argument, 0, 1004},
    {"max-pairs",       required_argument, 0, 1005},
    
    // 输出选项
    {"output",          required_argument, 0, 'o'},
    {"format",          required_argument, 0, 'f'},
    {"verbose",         no_argument,       0, 'v'},
    {"quiet",           no_argument,       0, 'q'},
    {"no-realtime",     no_argument,       0, 1006},
    
    // 分析选项
    {"no-dedup",        no_argument,       0, 1007},
    {"include-locked",  no_argument,       0, 1008},
    {"no-uaf",          no_argument,       0, 1009},
    
    // 其他
    {"help",            no_argument,       0, 'h'},
    {"version",         no_argument,       0, 1010},
    
    {0, 0, 0, 0}
};

static int parse_args(int argc, char* argv[], CollectorConfig* config) {
    int opt;
    int option_index = 0;
    
    while ((opt = getopt_long(argc, argv, "i:d:o:f:vqh", long_options, &option_index)) != -1) {
        switch (opt) {
            // 采样选项
            case 'i':
                config->interval_ms = atoi(optarg);
                if (config->interval_ms <= 0) {
                    fprintf(stderr, "Error: interval must be positive\n");
                    return -1;
                }
                break;
            case 'd':
                config->duration_sec = atoi(optarg);
                if (config->duration_sec < 0) {
                    fprintf(stderr, "Error: duration must be non-negative\n");
                    return -1;
                }
                break;
            
            // 检测阈值
            case 1001:  // --race-threshold
                config->race_time_threshold_ns = strtoull(optarg, NULL, 10);
                break;
            case 1002:  // --uaf-threshold
                config->uaf_time_threshold_ns = strtoull(optarg, NULL, 10);
                break;
            
            // 缓冲区设置
            case 1003:  // --trace-buffer
                config->trace_buffer_size_kb = atoi(optarg);
                break;
            case 1004:  // --max-records
                config->max_records = atoi(optarg);
                break;
            case 1005:  // --max-pairs
                config->max_race_pairs = atoi(optarg);
                break;
            
            // 输出选项
            case 'o':
                config->output_file = optarg;
                break;
            case 'f':
                if (strcmp(optarg, "csv") != 0 && strcmp(optarg, "json") != 0) {
                    fprintf(stderr, "Error: format must be 'csv' or 'json'\n");
                    return -1;
                }
                config->output_format = optarg;
                break;
            case 'v':
                config->verbose = true;
                break;
            case 'q':
                config->quiet = true;
                config->realtime = false;
                break;
            case 1006:  // --no-realtime
                config->realtime = false;
                break;
            
            // 分析选项
            case 1007:  // --no-dedup
                config->dedup_signals = false;
                break;
            case 1008:  // --include-locked
                config->skip_locked_pairs = false;
                break;
            case 1009:  // --no-uaf
                config->collect_uaf = false;
                break;
            
            // 其他
            case 'h':
                print_usage(argv[0]);
                exit(0);
            case 1010:  // --version
                print_version();
                exit(0);
            
            default:
                return -1;
        }
    }
    
    return 0;
}

// ============================================
// 打印配置信息
// ============================================
static void print_config(const CollectorConfig* config) {
    fprintf(stderr, "Configuration:\n");
    fprintf(stderr, "  Sampling interval:     %d ms\n", config->interval_ms);
    if (config->duration_sec > 0) {
        fprintf(stderr, "  Duration:              %d seconds\n", config->duration_sec);
    } else {
        fprintf(stderr, "  Duration:              until Ctrl+C\n");
    }
    fprintf(stderr, "  Race threshold:        %lu ns (%.2f ms)\n", 
            (unsigned long)config->race_time_threshold_ns,
            config->race_time_threshold_ns / 1000000.0);
    fprintf(stderr, "  UAF threshold:         %lu ns (%.2f s)\n", 
            (unsigned long)config->uaf_time_threshold_ns,
            config->uaf_time_threshold_ns / 1000000000.0);
    fprintf(stderr, "  Trace buffer:          %d KB per CPU\n", config->trace_buffer_size_kb);
    fprintf(stderr, "  Max records:           %d\n", config->max_records);
    fprintf(stderr, "  Max pairs:             %d\n", config->max_race_pairs);
    if (config->output_file) {
        fprintf(stderr, "  Output file:           %s (%s)\n", 
                config->output_file, config->output_format);
    }
    fprintf(stderr, "  Skip locked pairs:     %s\n", config->skip_locked_pairs ? "yes" : "no");
    fprintf(stderr, "  Collect UAF:           %s\n", config->collect_uaf ? "yes" : "no");
    fprintf(stderr, "  Dedup signals:         %s\n", config->dedup_signals ? "yes" : "no");
    fprintf(stderr, "\n");
}

// ============================================
// 主函数
// ============================================
int main(int argc, char* argv[]) {
    // 初始化配置
    CollectorConfig config;
    config_set_defaults(&config);
    
    // 解析命令行参数
    if (parse_args(argc, argv, &config) != 0) {
        print_usage(argv[0]);
        return 1;
    }
    
    // 检查权限
    if (geteuid() != 0) {
        fprintf(stderr, "Warning: This tool typically requires root privileges.\n");
        fprintf(stderr, "         Run with sudo if you encounter permission errors.\n\n");
    }
    
    // 打印配置
    if (config.verbose) {
        print_config(&config);
    }
    
    // 注册信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // 初始化收集器
    TraceCollector collector;
    if (collector_init(&collector, &config) != 0) {
        return 1;
    }
    
    // 初始化分析器
    RaceAnalyzer* analyzer = analyzer_create(&config);
    if (!analyzer) {
        fprintf(stderr, "Error: Failed to create analyzer\n");
        collector_cleanup(&collector);
        return 1;
    }
    
    // 初始化报告器
    Reporter reporter;
    reporter_init(&reporter, &config);
    
    // 切换到 LOG 模式
    if (collector_enable_log_mode(&collector) != 0) {
        fprintf(stderr, "Error: Failed to enable LOG mode\n");
        analyzer_destroy(analyzer);
        collector_cleanup(&collector);
        return 1;
    }
    
    // 清空初始的 trace buffer
    collector_clear_trace(&collector);
    
    // 打印启动信息
    if (!config.quiet) {
        fprintf(stderr, "╔════════════════════════════════════════════════════════════╗\n");
        fprintf(stderr, "║           syz-race-collector started                       ║\n");
        fprintf(stderr, "╠════════════════════════════════════════════════════════════╣\n");
        fprintf(stderr, "║  Sampling interval: %-6d ms                               ║\n", config.interval_ms);
        fprintf(stderr, "║  Race threshold:    %-10.2f ms                          ║\n", 
                config.race_time_threshold_ns / 1000000.0);
        if (config.duration_sec > 0) {
            fprintf(stderr, "║  Duration:          %-6d seconds                          ║\n", config.duration_sec);
        } else {
            fprintf(stderr, "║  Press Ctrl+C to stop and generate report                 ║\n");
        }
        fprintf(stderr, "╚════════════════════════════════════════════════════════════╝\n\n");
    }
    
    time_t start_time = time(NULL);
    uint64_t iteration = 0;
    
    // ========================================
    // 主循环
    // ========================================
    while (g_running) {
        iteration++;
        
        // 检查是否超时
        if (config.duration_sec > 0) {
            time_t elapsed = time(NULL) - start_time;
            if (elapsed >= config.duration_sec) {
                if (!config.quiet) {
                    fprintf(stderr, "\nDuration limit reached.\n");
                }
                break;
            }
        }
        
        // 1. 读取 trace buffer
        ssize_t bytes = collector_read_trace(&collector);
        
        // 2. 分析
        SampleResult sample = {0};
        sample.timestamp = time(NULL);
        sample.iteration = iteration;
        
        if (bytes > 0) {
            analyzer_process(analyzer, collector_get_buffer(&collector), 
                           collector_get_data_size(&collector), &sample);
        }
        
        // 3. 记录统计
        reporter_add_sample(&reporter, &sample);
        
        // 4. 清空 trace buffer
        collector_clear_trace(&collector);
        
        // 5. 等待下一个周期
        usleep(config.interval_ms * 1000);
    }
    
    // ========================================
    // 清理
    // ========================================
    
    // 切回 MONITOR 模式
    collector_disable_log_mode(&collector);
    
    // 生成最终报告
    reporter_generate_summary(&reporter);
    
    // 清理资源
    reporter_cleanup(&reporter);
    analyzer_destroy(analyzer);
    collector_cleanup(&collector);
    
    if (!config.quiet) {
        fprintf(stderr, "syz-race-collector stopped.\n");
    }
    
    return 0;
}
