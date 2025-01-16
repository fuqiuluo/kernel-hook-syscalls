//
// Created by 13723 on 24-12-22.
//

#ifndef TRS_TRACELOG_H
#define TRS_TRACELOG_H

#include <lyra/lyra.hpp>
#include <iostream>
#include <vector>

class TraceLog {
private:
    bool verbose = false;
    bool show_help = false;
    /**
     * The process id to trace.`
     *
     * 可以指定单个pid 123456
     * 也可以指定多个pid 123456,123457
     * 也可以指定pid范围 123456-123460
     * 也可以指定所有pid *
     */
    std::string pid = "*";
    /**
     * The user id to trace.
     *
     * 可以指定单个uid 123456
     * 也可以指定多个uid 123456,123457
     * 也可以指定所有uid *
     */
    std::string uid = "*";

    std::string output = "trace.log";
    std::string syscalls = "all";

    void checkParams();

    void doCommand(const lyra::group & g);
public:
    explicit TraceLog(lyra::cli & cli) {
        cli.add_argument(
                lyra::command("trace-log", [this](const lyra::group & g) {
                    this->doCommand(g);
                })
                .help("Record the specified syscall to the log file.")
                .add_argument(lyra::help(show_help))
                .add_argument(
                    lyra::opt(verbose)
                    .name("-v")
                    .name("--verbose")
                    .optional()
                    .help("Print more information.")
                )
                .add_argument(
                    lyra::opt(pid, "pid")["-p"]["--pid"]("The process id to trace.")
                    .hint("pid")
                    .optional()
                )
                .add_argument(
                    lyra::opt(uid, "uid")["-u"]["--uid"]("The user id to trace.")
                    .optional()
                    .hint("uid")
                )
                .add_argument(
                    lyra::opt(output, "output")["-o"]["--output"]("The output file.")
                    .optional()
                    .hint("output_path")
                )
                .add_argument(
                    lyra::opt(syscalls, "syscalls")["-s"]["--syscalls"]("The syscalls to trace.")
                    .optional()
                    .hint("syscall_names")
                )
        );
    }
};

#endif //TRS_TRACELOG_H
