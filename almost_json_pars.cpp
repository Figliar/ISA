//
// Created by rene on 2. 11. 2020.
// Functions for working with tesponses from server
//

#include <string>
#include <cstring>
#include "almost_json_pars.h"
using namespace std;

    // Vracia json cast z odpovede...
    string get_json_from_message(string messages){

        string needle = "\r\n[{\"";
        int found = messages.find(needle);
        string store;

        for(unsigned int i = found + 2; i <= messages.length(); i++){
            store += messages[i];
        }
        return store;
    }

    // Vracia hodnotu pomocou kluca what ("what": "hodnota")
    string get_from_body(string what, string buffer) {
        string json = get_json_from_message(buffer);
        string result = "";
        int match = 0;
        int json_len = json.length();
        int what_len = what.length();
        for (int i = 0; i <= json_len; i++) {
            if (what[0] == json[i]) {
                for (int j = 1; j <= what_len - 1; j++) {
                    if (what[j] != json[i + j]) {
                        match = 0;
                        break;
                    } else {
                        match = i + j;
                    }
                }
                if (match) {
                    while(json[match] != ':'){
                        match++;
                    }
                    while (true) {
                        if (json[match + 3] == '\"' and json[match + 2] != '\\' and json[match + 4] == ',') {
                            break;
                        } else {
                            result += json[match + 3];
                            match++;
                        }
                    }
                    break;
                }
            }
        }
        if (!result.empty()) {
            return result;
        } else {
            return "";
        }
    }

    // Vracia hodnotu pomocou kluca what z casti kde je where
    string get_from_body_whereis(string what, string where, string buffer) {
        string json = get_json_from_message(buffer);
        string result = "";
        size_t found = json.find(where);
        int match = 0;
        int what_len = what.length();
            while (json[found] != '{') {
                found--;
            }
            while(json[found] != '}'){
                found++;
                if(json[found] == what[0]){
                    for (int j = 1; j <= what_len - 1; j++) {
                        if (what[j] != json[found + j]) {
                            match = 0;
                            break;
                        } else {
                            match = found + j;
                        }
                    }
                    if (match) {
                        while (true) {
                            if (json[match + 5] == '\"') {
                                break;
                            } else {
                                result += json[match + 5];
                                match++;
                            }
                        }
                        if (!result.empty()) {
                            return result;
                        } else {
                            return "";
                        }
                    }
                }
            }
        return "";
    }
