// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include "reporter.h"

#include <stdlib.h>
#include <string.h>

void reporter_init(Reporter* r, const CollectorConfig* config) {
    memset(r, 0, sizeof(*r));
    r->config = config;
    r->start_time = time(NULL);
    r->first_sample = true;
    
    if (config->output_file) {
        r->output_fp = fopen(config->output_file, "w");
        if (!r->output_fp) {
            fprintf(stderr, "Warning: cannot open output file '%s'\n", config->output_file);
        } else if (strcmp(config->output_format, "csv") == 0) {
            // 写入 CSV 头（添加 VarNamePair 列）
            fprintf(r->output_fp, 
                "timestamp,elapsed_sec,iteration,access_count,free_count,"
                "race_pairs,unique_races_interval,total_unique_races,"
                "unique_varname_pairs,total_unique_varname_pairs,"
                "uaf_pairs,unique_uaf_interval,total_unique_uaf,"
                "unique_uaf_varname_pairs,total_unique_uaf_varname_pairs\n");
            fflush(r->output_fp);
        } else if (strcmp(config->output_format, "json") == 0) {
            // JSON 格式开头
            fprintf(r->output_fp, "{\n  \"samples\": [\n");
        }
    }
}

void reporter_add_sample(Reporter* r, const SampleResult* sample) {
    r->sample_count++;
    r->total_accesses += sample->access_count;
    r->total_frees += sample->free_count;
    r->total_race_pairs += sample->race_pair_count;
    r->total_uaf_pairs += sample->uaf_pair_count;
    r->last_unique_races = sample->total_unique_races;
    r->last_unique_uaf = sample->total_unique_uaf;
    r->last_unique_varname_pairs = sample->total_unique_varname_pairs;
    r->last_unique_uaf_varname_pairs = sample->total_unique_uaf_varname_pairs;
    
    int elapsed = (int)(sample->timestamp - r->start_time);
    
    // 写入到文件
    if (r->output_fp) {
        if (strcmp(r->config->output_format, "csv") == 0) {
            fprintf(r->output_fp, "%ld,%d,%lu,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n",
                    (long)sample->timestamp, elapsed, (unsigned long)sample->iteration,
                    sample->access_count, sample->free_count,
                    sample->race_pair_count, sample->unique_race_count, sample->total_unique_races,
                    sample->unique_varname_pairs, sample->total_unique_varname_pairs,
                    sample->uaf_pair_count, sample->unique_uaf_count, sample->total_unique_uaf,
                    sample->unique_uaf_varname_pairs, sample->total_unique_uaf_varname_pairs);
            fflush(r->output_fp);
        } else if (strcmp(r->config->output_format, "json") == 0) {
            if (!r->first_sample) {
                fprintf(r->output_fp, ",\n");
            }
            r->first_sample = false;
            fprintf(r->output_fp, 
                "    {\"timestamp\": %ld, \"elapsed_sec\": %d, \"iteration\": %lu, "
                "\"access_count\": %d, \"free_count\": %d, "
                "\"race_pairs\": %d, \"unique_races_interval\": %d, \"total_unique_races\": %d, "
                "\"unique_varname_pairs\": %d, \"total_unique_varname_pairs\": %d, "
                "\"uaf_pairs\": %d, \"unique_uaf_interval\": %d, \"total_unique_uaf\": %d, "
                "\"unique_uaf_varname_pairs\": %d, \"total_unique_uaf_varname_pairs\": %d}",
                (long)sample->timestamp, elapsed, (unsigned long)sample->iteration,
                sample->access_count, sample->free_count,
                sample->race_pair_count, sample->unique_race_count, sample->total_unique_races,
                sample->unique_varname_pairs, sample->total_unique_varname_pairs,
                sample->uaf_pair_count, sample->unique_uaf_count, sample->total_unique_uaf,
                sample->unique_uaf_varname_pairs, sample->total_unique_uaf_varname_pairs);
            fflush(r->output_fp);
        }
    }
    
    // 实时输出到 stdout（添加 VarNamePair 统计）
    if (r->config->realtime && !r->config->quiet) {
        printf("[%4lu] accesses=%-5d frees=%-3d races=%-3d (signals: +%-2d/%-4d, varnames: +%-2d/%-4d) "
               "uaf=%-2d (signals: +%-2d/%-3d, varnames: +%-2d/%-3d)\n",
               (unsigned long)sample->iteration,
               sample->access_count, sample->free_count,
               sample->race_pair_count, 
               sample->unique_race_count, sample->total_unique_races,
               sample->unique_varname_pairs, sample->total_unique_varname_pairs,
               sample->uaf_pair_count, 
               sample->unique_uaf_count, sample->total_unique_uaf,
               sample->unique_uaf_varname_pairs, sample->total_unique_uaf_varname_pairs);
        fflush(stdout);
    }
}

void reporter_generate_summary(Reporter* r) {
    time_t end_time = time(NULL);
    int duration = (int)(end_time - r->start_time);
    if (duration == 0) duration = 1;  // 避免除零
    
    // 写入 JSON 结尾和摘要
    if (r->output_fp && strcmp(r->config->output_format, "json") == 0) {
        fprintf(r->output_fp, "\n  ],\n");
        fprintf(r->output_fp, "  \"summary\": {\n");
        fprintf(r->output_fp, "    \"start_time\": %ld,\n", (long)r->start_time);
        fprintf(r->output_fp, "    \"end_time\": %ld,\n", (long)end_time);
        fprintf(r->output_fp, "    \"duration_seconds\": %d,\n", duration);
        fprintf(r->output_fp, "    \"sample_count\": %lu,\n", (unsigned long)r->sample_count);
        fprintf(r->output_fp, "    \"total_accesses\": %lu,\n", (unsigned long)r->total_accesses);
        fprintf(r->output_fp, "    \"total_frees\": %lu,\n", (unsigned long)r->total_frees);
        fprintf(r->output_fp, "    \"total_race_pairs\": %lu,\n", (unsigned long)r->total_race_pairs);
        fprintf(r->output_fp, "    \"total_unique_races\": %d,\n", r->last_unique_races);
        fprintf(r->output_fp, "    \"total_unique_varname_pairs\": %d,\n", r->last_unique_varname_pairs);
        fprintf(r->output_fp, "    \"total_uaf_pairs\": %lu,\n", (unsigned long)r->total_uaf_pairs);
        fprintf(r->output_fp, "    \"total_unique_uaf\": %d,\n", r->last_unique_uaf);
        fprintf(r->output_fp, "    \"total_unique_uaf_varname_pairs\": %d,\n", r->last_unique_uaf_varname_pairs);
        fprintf(r->output_fp, "    \"avg_races_per_second\": %.2f,\n", 
                (double)r->total_race_pairs / duration);
        fprintf(r->output_fp, "    \"avg_accesses_per_second\": %.2f\n", 
                (double)r->total_accesses / duration);
        fprintf(r->output_fp, "  }\n");
        fprintf(r->output_fp, "}\n");
    }
    
    // 输出到 stderr（添加 VarNamePair 统计）
    if (!r->config->quiet) {
        fprintf(stderr, "\n");
        fprintf(stderr, "╔════════════════════════════════════════════════════════════╗\n");
        fprintf(stderr, "║              Race Collection Summary                       ║\n");
        fprintf(stderr, "╠════════════════════════════════════════════════════════════╣\n");
        fprintf(stderr, "║  Duration:              %-10d seconds                  ║\n", duration);
        fprintf(stderr, "║  Samples collected:     %-10lu                         ║\n", (unsigned long)r->sample_count);
        fprintf(stderr, "╠════════════════════════════════════════════════════════════╣\n");
        fprintf(stderr, "║  Total accesses:        %-10lu                         ║\n", (unsigned long)r->total_accesses);
        fprintf(stderr, "║  Total frees:           %-10lu                         ║\n", (unsigned long)r->total_frees);
        fprintf(stderr, "║  Avg accesses/sec:      %-10.2f                         ║\n", 
                (double)r->total_accesses / duration);
        fprintf(stderr, "╠════════════════════════════════════════════════════════════╣\n");
        fprintf(stderr, "║  Total race pairs:      %-10lu                         ║\n", (unsigned long)r->total_race_pairs);
        fprintf(stderr, "║  Unique signals:        %-10d (var+stack 4-tuple)     ║\n", r->last_unique_races);
        fprintf(stderr, "║  Unique VarName pairs:  %-10d (var 2-tuple, fuzzer)   ║\n", r->last_unique_varname_pairs);
        fprintf(stderr, "║  Avg races/sec:         %-10.2f                         ║\n", 
                (double)r->total_race_pairs / duration);
        fprintf(stderr, "╠════════════════════════════════════════════════════════════╣\n");
        fprintf(stderr, "║  Total UAF pairs:       %-10lu                         ║\n", (unsigned long)r->total_uaf_pairs);
        fprintf(stderr, "║  Unique UAF signals:    %-10d (var+stack 4-tuple)     ║\n", r->last_unique_uaf);
        fprintf(stderr, "║  Unique UAF VarNames:   %-10d (var 2-tuple, fuzzer)   ║\n", r->last_unique_uaf_varname_pairs);
        fprintf(stderr, "╚════════════════════════════════════════════════════════════╝\n");
        fprintf(stderr, "\nNote: 'VarName pairs' metric matches the fuzzer's counting method.\n");
    }
    
    if (r->config->output_file && r->output_fp) {
        fprintf(stderr, "Results written to: %s\n", r->config->output_file);
    }
}

void reporter_cleanup(Reporter* r) {
    if (r->output_fp) {
        fclose(r->output_fp);
        r->output_fp = NULL;
    }
}
