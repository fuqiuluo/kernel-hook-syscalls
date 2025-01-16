#include <lyra/lyra.hpp>

#include "Commands/TraceLog.h"

int main(int argc, char* argv[]) {
    auto cli = lyra::cli();
    bool show_help = false;
    cli.add_argument(lyra::help(show_help));
    TraceLog traceLog { cli };
    auto result = cli.parse( { argc, argv } );
    if (show_help || argc == 1) {
        std::cout << cli;
        return 0;
    }
    if (!result) {
        std::cerr << result.message() << "\n";
    }
    return result ? 0 : 1;
}