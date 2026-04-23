#!/bin/bash

# 遍历所有 workdir-* 目录，将 uaf-corpus.db 重命名为 uaf-corpus.db.N

for dir in workdir-*/; do
    db_file="${dir}uaf-corpus.db"
    
    if [[ -f "$db_file" ]]; then
        # 找到下一个可用的编号
        n=1
        while [[ -f "${db_file}.${n}" ]]; do
            ((n++))
        done
        
        new_name="${db_file}.${n}"
        echo "重命名: $db_file -> $new_name"
        mv "$db_file" "$new_name"
    fi
done

echo "完成!"
