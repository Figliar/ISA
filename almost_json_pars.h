//
// Created by rene on 8. 11. 2020.
// Functions for working with tesponses from server
//

#include <string>

#ifndef DISCORDBOT_ALMOST_JSON_PARS_H
#define DISCORDBOT_ALMOST_JSON_PARS_H

    std::string get_json_from_message(std::string __messages);

    std::string get_from_body(std::string what, std::string buffer);

    std::string get_from_body_whereis(std::string what, std::string where, std::string buffer);

#endif //DISCORDBOT_ALMOST_JSON_PARS_H
