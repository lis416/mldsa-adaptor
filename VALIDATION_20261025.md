# 2026-10-25 论文与实验最终验收

审查起点：Fable 提交 6ccac360f55992ca5f6147e485989e412a4e4fd7。
工作分支：codex/artifact-review-20261025。
本轮实际测试的源码提交：159235d71a1cf71d8a94d2e8c7b81720f1d5ecf8。

## 结论

本轮修改、实验归档和最小复现已完成。没有发现需要推翻核心构造或证明链的新问题。Fable 已落实主要审查意见；本轮再修正了少量范围和实验措辞，并使数值脚本的最终认证比较严格使用精确有理数。

英文 PDF 为 21 页，引用和版面检查通过。公开边界实验已正式加入 Cargo 入口并复跑，结果与历史记录完全一致。发布前仍需真实 GitHub 仓库链接和作者选定的项目许可证；本轮未发布到 GitHub。

## 已修正内容

1. 摘要的 2^-204 模拟误差界补回“理想掩码”条件。
2. 引言使用明确的 NTT 分量满列秩条件，避免把约 2^-15 的奇异概率写成精确比例；删除无噪声恢复的笼统运行时间措辞。
3. naive-mask 结果精确描述为 4980/20000 个短响应差，并逐项验证其等于 (c-c')s1；不声称工具直接记录了相同接受轮数或实现了完整密钥恢复。
4. capped_bound.py 将最终的二进制阈值比较改为 Fraction 的精确比较。正向 Decimal 运算仍采用 450 位向上舍入；避免右侧阈值也向上舍入后产生形式上的认证漏洞。原论文数值有充足裕量，本轮结果没有改变。
5. 无噪声恢复脚本显式检查全部 NTT 分量满秩，并在恢复失败时退出失败；UseHint 穷举输出精确计数，并在发现反例时退出失败。
6. 新增可运行的 src/bin/public_boundary.rs、历史输出、来源说明、artifact 总入口、复现指令及独立批次说明；修正 README 旧版节号、Adapt 检查说明与实验范围。

签名、预签名、适配、提取和三个验证器的核心实现未修改。历史主实验日志保留原样。

## 本轮实际执行的验证

| 项目 | 结果 |
|---|---|
| Rust release / locked / offline 测试 | 8 项核心测试全部通过，0 失败 |
| §4.7 公开边界探针 | seed=20261019，20,000 对；普通签名触发 106，适配签名触发 0 |
| 公开探针与历史输出比较 | 完整结果行逐字一致 |
| ML-DSA-44 UseHint 穷举 | 83,801,080 个满足 C 的组合，0 反例 |
| ML-DSA-65 UseHint 穷举 | 150,843,744 个满足 C 的组合，0 反例 |
| ML-DSA-87 UseHint 穷举 | 83,803,040 个满足 C 的组合，0 反例 |
| 无噪声关系恢复 | seed=7，256/256 个 NTT 分量满秩，恢复值与原见证相等 |
| 模拟界复算 | 2^-204、2^-846、2^-1258 均通过精确阈值比较 |
| 英文编译 | 三遍 pdflatex，21 页；无未定义引用、重复标签、overfull 或 rerun 提示 |
| PDF 视觉检查 | 检查全部 21 页版面及 §4.7 所在第 14 页细节，未见截断或重叠 |

公开探针本轮输出：

~~~text
seed=20261019 n=20000 fresh_boundary=106 adapted_boundary=0 rate=0.00530000 wilson95=[0.00438435,0.00640565]
~~~

普通签名触发率 0.530%，Wilson 95% 区间 [0.4384%, 0.6406%]。这是同种子的复现，不是新增独立样本，不能与历史批次相加称为 40,000 对。该检验只使用公开的密钥和签名，不使用见证或 t0；生成适配样本时使用见证与检验器的输入不同。

模拟界的显示值：

| 参数 | 截断 D | log2 epsilon_D | log2 delta_D | log2 总模拟误差上界 |
|---|---:|---:|---:|---:|
| ML-DSA-44 | 11 | -409.392733 | -209.196222 | -204.341974 |
| ML-DSA-65 | 44 | -1115.925919 | -867.156919 | -846.925918 |
| ML-DSA-87 | 63 | -1591.986806 | -1268.342885 | -1258.984606 |

这些数值仅对应模拟项，不能解释成整个方案具有相应位数的安全性。公开探针的触发率也不是最优公开区分器的优势上界。

## 可复核的记录

在论文仓库 paper-repo/ 下：

- artifact/mldsa_adaptor/results/cargo_test_release_20261025.txt
- artifact/mldsa_adaptor/results/public_boundary_seed20261019_rerun_20261025.txt
- artifact/mldsa_adaptor/results/public_boundary_seed20261019_historical.txt
- artifact/mldsa_adaptor/results/public_boundary_PROVENANCE.md
- artifact/mldsa_adaptor/results/validation_20261025.json
- artifact/analysis/results/capped_bound_20261025.txt
- artifact/analysis/results/naive_attack_20261025.txt
- artifact/analysis/results/lemma1_check_20261025.txt
- artifact/analysis/results/validation_20261025.json
- artifact/validation/paper_build_20261025.json

Rust 验证在工地执行：rustc 1.99.0、cargo 1.99.0，使用锁文件、离线构建与一个构建任务。Python 验证在独立的 8 GiB 内存环境执行：Python 3.12.14、NumPy 2.3.5；未将完整 NumPy 穷举施加到工地的 2 GiB 主机。相关环境、源码哈希、命令与退出状态均已记录。

本轮没有重跑此前两组大规模主实验，也没有把未做过的 ML-DSA-65/87 互操作、端到端密钥恢复、QROM、尾界、额外格实例估计或侧信道审计写成已完成。

## 尚需发布时落实的事项

- macros.tex 中的真实 GitHub 地址；当前仍为占位链接。
- 项目自身许可证由作者决定，现有第三方许可证保留。
- 英文为本轮验收版本，中文版未同步这些修改。
- 提供给审查的源码保留作者占位，正式上传时使用作者自己的完整署名版本。

GitHub 连接尚未建立，因此没有创建远端仓库、推送或公开任何材料。旧的访问审批问题已在本轮授权后解除，论文源码和三个 Python 脚本已经完成读取；不存在继续等待读取授权的事项。

