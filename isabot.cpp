/*
 * Autor: René Rešetár (xreset00)
 * Projekt pre: Síťové aplikace a správa sítí
 * Programování síťové služby
 * Zadanie: Varianta termínu - Discord bot (Ing. Jeřábek)
 * Kod bol inspirovany: https://gist.github.com/raschupkin/88a1ff730bcfa1c5a12d5804bbf451c9
 */

/*
 * INCLUDE SECTION
 */
#include <iostream>
#include <getopt.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <cstring>
#include <unistd.h>
#include <netdb.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string>
#include <netinet/in.h>
#include <regex>
#include <cstdlib>
#include <cstdio>

#include <utility>
#include "almost_json_pars.h"
bool DEBUG = false;
using namespace std;

/* Function for printing errors */
void error(const char *msg){
    fprintf(stderr, "%s", msg);
    exit(1);
}

/* My structures used in code */
struct Connection{
    string guild_id;
    string channel_id;
    string channel_name;
    string last_message_id;
    string token;
    string message_content;
    bool out{};
};

struct Vectors{
    vector<string> contents;
    vector<string> usernames;
};

//---------------------------------------------------------------------------------------------//
//  *  *  *  *  *  *  *  *  *  *  *  *   FUNCTIONS   *  *  *  *  *  *  *  *  *  *  *  *  *  *  //
//---------------------------------------------------------------------------------------------//

SSL *ssl;
int sock;
#define PORT 443

/*
 * Funkcia ktora kontroluje x-ratelimit-ramaining a zistuje ci mozeme poslat dalsi request
 * Ak je limit 0 pozrie sa na x-ratelimit-reset-after a uspi program na danu hodnotu
 * Ak sa x-ratelimit-reset-after nenajde uspi program na 5 seckund
 */
void check_if_sleep(string msgs){
    int found = msgs.find("x-ratelimit-remaining: ");
    int found_2 = msgs.find("x-ratelimit-reset-after: ");
    if(found != -1) {
        if(found_2 != -1) {
            if (msgs[found + 23] == '0') {
                char help = msgs[found_2 + 25];
                int i = atoi(&help);
                sleep(i);
//        if (msgs[found + 23] == '1'){
//            sleep(1);
//        }
//        else if(msgs[found + 23] == '0') {
//            sleep(3);
            }
        }
        else{
            sleep(5);
        }
    }
}

/*
 * Funkcia na kontrola casti priatej odpovede zistuje ci je sprava relevantna
 */
string check_chunk(string ch, int l){
    if(regex_search(ch, regex("(.*)\"message\": \"401: Unauthorized\", \"code\": 0(.*)"))) {
        error("Error, wrong response\n");
    }
    if(regex_search(ch, regex("(.*)\"message\": \"404: Not Found\", \"code\": 0(.*)"))) {
        error("Error, wrong response\n");
    }
    if(regex_search(ch, regex("(.*)403 Forbidden(.*)"))) {
        error("Error, wrong response\n");
    }
    if(regex_search(ch, regex("(.*)Content-Length: 2\r\n(.*)")) or l <= 0){
        return "";
    }
    if(regex_search(ch, regex("\"You are being rate limited.\","))){
        sleep(3);
        return "";
    }
    return "0";
}

/*
 * Funkcia na posielanie requestu a vratenie odpovede pomocou SSL_read()
 */
string RecvPacket() {

    // Cast kodu z: https://gist.github.com/raschupkin/88a1ff730bcfa1c5a12d5804bbf451c9
    // upravena
    int len;
    char buf[2048];
    string chunk;
    string result = "";
    do {
        // Nastavenie pamate bufferu, citanie odpovede a jej zapis do result
        memset(buf, '\0', sizeof(buf));
        len = SSL_read(ssl, buf, sizeof(buf));
        buf[len] = 0;
        chunk = buf;
        check_if_sleep(chunk);
        // Kontrola niektorych moznych chybovych odpovedi
        if(check_chunk(chunk, len).empty()) return "";
        // Dopísanie chunku do odpovede
        if (len > 0) result.append(buf);
        // Kontrola pripadnych zlyhani SSL_read()
        if (len < 0) {
            int err = SSL_get_error(ssl, len);
            if (err == SSL_ERROR_WANT_READ)
                error("err == SSL_ERROR_WANT_READ");
            if (err == SSL_ERROR_WANT_WRITE)
                error("err == SSL_ERROR_WANT_WRITE");
            if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL)
                error("err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL");
        }
    // Slucka ktora bezi dokedy nenarazime na koniec odpovede
    } while (!regex_search(chunk, regex("(.*)0\r\n\r\n")));
    // Vraciame celu odpoved
    return result;
}

/*
 * Funkcia pre zasielanie requestov pomocou SSL_write()
 */
int SendPacket(const char *buf)
{
    // Cast kodu z: https://gist.github.com/raschupkin/88a1ff730bcfa1c5a12d5804bbf451c9
    // neupravena
    int len = SSL_write(ssl, buf, strlen(buf));
    // Kontrola poctu vratenych bytov
    if (len < 0) {

        int err = SSL_get_error(ssl, len);
        switch (err) {
            case SSL_ERROR_WANT_WRITE:
                return 0;
            case SSL_ERROR_WANT_READ:
                return 0;
            case SSL_ERROR_ZERO_RETURN:
            case SSL_ERROR_SYSCALL:
            case SSL_ERROR_SSL:
            default:
                return 1;
        }
    }
    return 0;
}

/*
 * Funkcia volana pri neuspesnom vytvoreni ssl, pre vypis objavenej chyby
 */
void log_ssl()
{
    // Cast kodu z: https://gist.github.com/raschupkin/88a1ff730bcfa1c5a12d5804bbf451c9
    // neupravena
    int err;
    while ((err = ERR_get_error())) {
        char *str = ERR_error_string(err, 0);
        if (!str)
            return;
        fprintf(stderr, "%s",str);
        fprintf(stderr, "\n");
        fflush(stderr);
    }
}

/*
 * Funkcia na ziskanie spravnych informacii o novych spravach (meno odosielatela, obsah spravy)
 */
Vectors get_msg_info(string msgs){
    //Inicializacia potrebnych pomocnych premennych
    string username;
    string content;
    Vectors vectors;    // Info o spravach ukladam do struktury Vectors, aby som ich potom mohol citat odzadu
    int found = 1;

    // Kym find najde v odpovedi "id" sme v loope
    string needle = ", {\"id\"";
    while(found != -1){
        username = get_from_body("\"username\"", msgs);
        content = get_from_body("\"content\"", msgs);
        // Pokial username obsahuje podretazec bot tak spravu ignorujeme a ideme dalej
        if(regex_match(username, regex("(.*)bot(.*)"))){
            found = msgs.find(needle);
            // Orezeme spravu o cast ktoru sme uz spracovali
            msgs.erase(0,found + 10);
            continue;
        }
        // Ak username neobsahuje bot podretazec pushujeme hodnoty username a content do vectorov
        vectors.usernames.push_back(username);
        vectors.contents.push_back(content);

        // Odpoved skratime o cast z ktorej sme uz ziskali informacie
        found = msgs.find(needle);
        msgs.erase(0,found + 10);
    }
    // Na konci vratime strukturu Vectors
    return vectors;
}

/*
 * Funkcia sluzi na odosielanie POST requestov s odpovedou na nove spravy
 */
void send_msgs(Vectors vectors, Connection co){
    // Iterujem cez vsetky prvky vo vektoroch odzadu
    auto y = vectors.contents.rbegin();
    for(auto i = vectors.usernames.rbegin(); i != vectors.usernames.rend();) {
        // Ak bol pri spusteni pritomny argument -v alebo --verbose
        // tak vypisujeme na stdout
        if(co.out) {
            cout << co.channel_name << " - " << *i << ": " << *y << endl;
        }

        // Z prvkov vektorov poskladame spravu v json formate
        co.message_content = "{\"content\": \"echo ";
        co.message_content.append(*i);
        co.message_content.append(" - ");
        co.message_content.append(*y);
        co.message_content.append("\", \"tts\": false}");

        if(co.message_content.length() <= 2000) {
            // Poskladame request
            string msg = "POST /api/v6/channels/";
            msg.append(co.channel_id);
            msg.append("/messages HTTP/1.1\r\nHost: discord.com\r\nAuthorization: Bot ");
            msg.append(co.token);
            msg.append("\r\nContent-Type: application/json\r\nContent-Length: ");
            msg.append(std::to_string(co.message_content.length()));
            msg.append("\r\n\r\n");
            msg.append(co.message_content);
            msg.append("\r\n\r\n");

            // Zasielame a na sekundu cakame aby sme nezahltili server a nedoslo k chybe
            SendPacket(msg.c_str());
            string res = RecvPacket();
        }
        else{
            cout<<"Cannot send message to Discord. It has "<<co.message_content.length()<<" out of 2000 characters allowed!"<<endl;
        }
        // Presunieme sa na dalsie prvky vektorov
        ++i; ++y;
    }
}

/*
 * Funkcia pre spracovanie novych sprav na channeli
 */
int handle_messages(string msgs, Connection c){

    // Odpoved z get_msg_info ulozim do Vectors struktury
    // aby som ju mohol predat do send_msgs ako parameter
    Vectors vecs = get_msg_info(std::move(msgs));
    send_msgs(vecs, std::move(c));

    return 0;
}

/*
 * Funkcia pre ziskanie vsetkych potrebnych IDcok
 */
void get_basic_info(struct Connection *c){

//------------------- GET MY GUILD ----------------------------------//
    if(DEBUG)
        cout<<"Getting my guilds..."<<endl;
    string msg = "GET /api/v6/users/@me/guilds HTTP/1.1\r\nHost: discord.com\r\nAuthorization: Bot ";
    msg.append(c->token);
    msg.append("\r\n\r\n");

    SendPacket(msg.c_str());
    string guilds = RecvPacket();

    if(guilds.empty()){
        error("Error getting guilds\n");
    }
    // Volame get_from_body pre ziskanie id
    c->guild_id = get_from_body("id", guilds);
    if(DEBUG)
        cout<<"DONE"<<endl;

//------------------- GET CHANNELS OF GUILD --------------------------//
    if(DEBUG)
        cout<<"Getting isa-bot channel id... "<<endl;
    msg = "GET /api/v6/guilds/";
    msg.append(c->guild_id);
    msg.append("/channels HTTP/1.1\r\nHost: discord.com\r\nAuthorization: Bot ");
    msg.append(c->token);
    msg.append("\r\n\r\n");

    SendPacket(msg.c_str());
    string channels = RecvPacket();

    if(channels.empty()){
        error("Error getting channels\n");
    }
    // Volame get_from_body_where pre ziskanie id a mena zo zaznamu patriacemu hladanemu channelu
    c->channel_id = get_from_body_whereis("id", "isa-bot", channels);
    c->channel_name = get_from_body_whereis("name", "isa-bot", channels);
    if(DEBUG)
        cout<<"DONE"<<endl;

//------------------- GET LAST MESSAGE ID --------------------------//
    if(DEBUG)
        cout<<"Getting last_message_id to get started..."<<endl;
    msg = "GET /api/v6/channels/";
    msg.append(c->channel_id);
    msg.append("/messages?limit=1 HTTP/1.1\r\nAuthorization: Bot ");
    msg.append(c->token);
    msg.append("\r\nHost: discord.com\r\n\r\n");

    SendPacket(msg.c_str());
    string messages = RecvPacket();

    if(messages.empty()){
        error("Error getting messages\n");
    }
    // Volame get_from_body pre ziskanie id
    c->last_message_id = get_from_body("id", messages);
    if(DEBUG) {
        printf("guild_id:    %s\nchannel_id:         %s\nlast_message_id:    %s\n",
               c->guild_id.c_str(), c->channel_id.c_str(), c->last_message_id.c_str());
    }
}

/*
 * Funkcia na verifikaciu spravnosti tokenu pomocou requestu GET /api/v6/users/@me HTTP/1.1
 */
int check_token(const string& token){
    if(DEBUG)
        cout<<"Verifying your token..."<<endl;

    // Prvotna kontroladlzky tokenu
    if(token.length() != 59) error("Error, wrong token\n");
    string msg = "GET /api/v6/users/@me HTTP/1.1\r\nAuthorization: Bot ";
    msg.append(token);
    msg.append("\r\nHost: discord.com\r\n\r\n");

    SendPacket(msg.c_str());
    // Token sa skontroluje v RecvPacket() kde su osetrenu chybove stavy
    string response = RecvPacket();

    if(response.empty())
        error("Error, getting info about @me\n");

    if(DEBUG)
        cout<<"DONE"<<endl;
    return 0;
}
/*
 * Funkcia na vytvorenie socketu a inicializaciu spojenia zo serverom pomocou SSL
 */
int initialize_bot(){

    // Cast kodu z: https://gist.github.com/raschupkin/88a1ff730bcfa1c5a12d5804bbf451c9
    // upravena
    if(DEBUG)
        cout<<"Initializing bot..."<<endl;

    // Inicializacia socketu
    int s;
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)  error("Error creating socket.\n");

    // Nastavenie spojenia: adresa, port, family,...
    sockaddr_in sa{};
    memset (&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    string IP = inet_ntoa(*((struct in_addr*)gethostbyname("discord.com")->h_addr_list[0]));
    sa.sin_addr.s_addr = inet_addr(IP.c_str());
    sa.sin_port        = htons (PORT);
    socklen_t socklen = sizeof(sa);
    if (connect(s, (struct sockaddr *)&sa, socklen)) error("Error connecting to server.\n");

    // Libssl inicializacia
    SSL_library_init();
    SSLeay_add_ssl_algorithms();
    SSL_load_error_strings();

    // Inicializacia konkretnej metody
    const SSL_METHOD *meth = TLSv1_2_client_method();
    SSL_CTX *ctx = SSL_CTX_new (meth);
    if(ctx == nullptr) error("Error calling SSL_CTX_new()\n");
    ssl = SSL_new (ctx);

    if (!ssl) {
        fprintf(stderr, "Error creating SSL.\n");
        log_ssl();
        return 1;
    }

    sock = SSL_get_fd(ssl);
    SSL_set_fd(ssl, s);
    int err = SSL_connect(ssl);

    if (err <= 0) {
        fprintf(stderr, "Error creating SSL connection.  err=%x\n", err);
        log_ssl();
        fflush(stderr);
        return 1;
    }
    // Pri uspesnej inicializacii vrati 0
    return 0;
}

/*
 * Funkcia ktory predstavuje bota (obsahuje nekonecny while loop)
 * a kde sa volaju vsetky potrebne funkcie na spravny chod
 */
int bot(Connection con){

//-------------- INITIALIZATION OF CONNECTION ----------------------//

    initialize_bot();

//-------------- INITIALIZATION OF CONNECTION ----------------------//

    check_token(con.token);

//------------------ GETTING NEEDED IDS ----------------------------//

    get_basic_info(&con);
    if(DEBUG)
        cout<<"DONE"<<endl;

//------------------- HANDLE NEW MESSAGES --------------------------//

// Ignorujeme nekonecnu slucku
    string messages_after;
    if(DEBUG)
        cout<<"Running bot..."<<endl;
    string msg;
    // Kazdu sekundu zasleme request ci sa na channeli objavili nejake nove spravy
    // po nasej doterajsej poslednej sprave
    do {
        msg = "GET /api/v6/channels/";
        msg.append(con.channel_id);
        msg.append("/messages?after=");
        msg.append(con.last_message_id);
        msg.append(" HTTP/1.1\r\nAuthorization: Bot ");
        msg.append(con.token);
        msg.append("\r\nHost: discord.com\r\n\r\n");
        SendPacket(msg.c_str());

        // Ak dostaneme nedostaneme prazdnu odpoved
        messages_after = RecvPacket();
        // Zistime ci mozeme zaslat request

        if(!messages_after.empty()) {
            // Ziskame nove id poslednej spravy
            con.last_message_id = get_from_body("\"id", messages_after);
            // Volame handle_messages na spracovanie a odoslanie odpovede
            handle_messages(get_json_from_message(messages_after), con);
            // Vycistime spravy
            messages_after.clear();
        }
    //Opakujeme kým nepríde signál na ukončenie (Ctrl+c)
    }while(true);
}

//---------------------------------------------------------------------------------------------//
//  *  *  *  *  *  *  *  *  *  *  *  *  *   MAIN   *  *  *  *  *  *  *  *  *  *  *  *  *  *  * //
//---------------------------------------------------------------------------------------------//

int main(int argc, char *argv[]) {

    //Inicializacia pomocnych premennych: c => kotrola argumentov,
    //connect => struktura na predavanie informacii v kode
    int c;
    Connection connect;

    // Urcenie prijatelnych argumentov
    static struct option long_options[] =
            {
                    {"help", optional_argument, nullptr, 'h'},
                    {"verbose", optional_argument, nullptr, 'v'},
                    {nullptr, 0, nullptr, 0}
            };

    // Parsovanie argumentov pomocou getopt()
    while ((c = getopt_long(argc, argv, "vht:s", long_options, nullptr)) != EOF) {
        switch(c){
            // Vypise help pomocku pre uzivatela
            case 'h':
                cout << "Program isabot bude načúvať na Discord kanáli s menom #isa-bot a to\n"
                        "na servery kde sa nachádza bot ktorého token použijete.\n\n"
                        "-h|--help : Vypíše nápovědu na standardní výstup.\n"
                        "-v|--verbose : Bude zobrazovat zprávy, na které bot reaguje na standardní výstup ve formátu \"<channel> - <username>: <message>\".\n"
                        "-t <bot_access_token> : Zde je nutno zadat autentizační token pro přístup bota na Discord.\n"
                        "Bot sa ukončuje pomocou Ctrl + c" << endl;
                return 1;
            // "Zapne" vypisovanie na stdout
            case 'v':
                connect.out = true;
                break;
            // Skontroluje token
            case 't':
                connect.token = optarg;
                break;
            default:
                error("Error, wrong arguments!\n");
        }
    }
    if(connect.token.empty()){
        cout << "Program isabot bude načúvať na Discord kanáli s menom #isa-bot a to\n"
                "na servery kde sa nachádza bot ktorého token použijete.\n\n"
                "-h|--help : Vypíše nápovědu na standardní výstup.\n"
                "-v|--verbose : Bude zobrazovat zprávy, na které bot reaguje na standardní výstup ve formátu \"<channel> - <username>: <message>\".\n"
                "-t <bot_access_token> : Zde je nutno zadat autentizační token pro přístup bota na Discord.\n"
                "Bot sa ukončuje pomocou Ctrl + c" << endl;
        return 1;
    }
    bot(connect);
    return 0;
}