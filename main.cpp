#include <iostream>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <cstring>
#include <cstdio>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <cstdlib>
#include <cerrno>
#include <arpa/inet.h>
#include <ctime>
using namespace std;
struct OptArray {
    //Here are the default options of the program.
    //They are arranged in pairs, with the boolean
    //switches being the "flags" and the strings /
    //integers being the arguments.
    bool FileSwitch = false;                            //If there will be a file with a proxy list
    char FilePath[100] = "";                            //and where
    bool TimeoutSwitch = false;                         //If there is a manual timeout
    struct timeval Timeout;                             //and how long (in seconds)
    bool OutputSwitch = false;                          //If the program will output the active proxy list
    char OutputPath[100] = "";                          //and where
    bool CheckSiteSwitch = false;                       //If there will be another site to check the proxies against
    char CheckSite[100] = "www.secmaniac.org";          //and which it will be (secmaniac.org by default)
    char IPAddress[16] = "0.0.0.0";                     //In case we want to check a specific proxy only, its IP address
    int  Door = 80;                                     //and its port
    char *Texttosend = NULL;                            //The pointer to the string to send
    int  SizeToSend = 0;                                //and the size of said string
    bool  Verbosity = true;                             //Verbosity level - false: quiet, true: noisy
} Options;

bool checkarg(char* first, char* second, int optcode)
{  //An ugly options sanity checker
    if (first == second) return true;       //If the switch is the last option, without argument when it has to have one.
    if (*second == '-') return true;        //If the next option is a switch when there should be an argument
    if (optcode == 2) {                     //If the optcode is 2,check if the "second" variable is number, returning true if it is not
        if ((*second <'0') || (*second >'9')) return true;
    }
    return false;
}

void httpstrip (OptArray* Opts)             //Normalize the check site
{                                           //Ugly piece of code, needs polishing
    char *tmp;
    char temp[120];
    if (*(Opts->CheckSite) == 'h'){
            if (!strncmp(Opts->CheckSite, "http://",7)) {   //Basically, just remove the
                    strcpy(temp, (Opts->CheckSite)+8);      //"http://" thing
            }
        }
    tmp = temp;
    while(*tmp != '\0') {tmp++;}
    if (*(tmp - 1) == '/') {*(tmp-1) = '\0' ;}              //and the "/" from the end, if any
    strcpy(Opts->CheckSite, temp);
    return;
}

int parser (char* c){
    //An ugly parser to catch the argument switches
    //Input is the pointer to the start of the argument
    //output is a numerical code for identified option
    //or 0 if not recognized
    if (!strcmp(c, "-f")) return 1;
    if (!strcmp(c, "-t")) return 2;
    if (!strcmp(c, "-o")) return 3;
    if (!strcmp(c, "-c")) return 4;
    if (!strcmp(c, "-h")) return 5;
    if (!strcmp(c, "-q")) return 6;
    if (*(c+1)=='-'){         //In case we have the double dash argument format
        if (!strcmp(c, "--file")) return 1;
        if (!strcmp(c, "--timeout")) return 2;
        if (!strcmp(c, "--output")) return 3;
        if (!strcmp(c, "--check")) return 4;
        if (!strcmp(c, "--help")) return 5;
        if (!strcmp(c, "--quiet")) return 6;
    }
    return 0;
}

void help(){     //Just prints the help text. Under construction.
    cout << "\nUnder construction.\n";
    return;
}


class Proxy {                                           //This is the main class to fill and check
    int RecordedLatency;                                //The latency of the connection time
    bool Active;                                        //If the proxy is up or not
    sockaddr_in Address;                                //The IP Address structure
    char IPAddr[16];                                    //The IP address as a string
    int IPDoor;                                         //and the TCP port
public:                                                 //Here are the typical methods for entering and extracting data
    bool IsActive() {return Active;}
    void SetActive(bool a) {Active = a;}
    void SetIP(char* c){                                //Still need a sanity check
        strcpy(IPAddr,c);
        Address.sin_addr.s_addr = inet_addr(c);
    }
    char* ReturnIP() {
        return inet_ntoa(Address.sin_addr);
    }
    void SetPort(int i){
        IPDoor = i;
        Address.sin_port = htons(i);
    }
    int ReturnPort(){
        return ntohs(Address.sin_port);
    }
    void SetRecordedLatency(int i){
        RecordedLatency = i;
    }
    int ReturnRecordedLatency(){
        return RecordedLatency;
    }
    Proxy()                                             //And the constructor
    {                                                   //for no-argument setup
        Address.sin_port = htons(0);                    //Sets the defaults: IP address 0.0.0.0
        IPDoor = 0;                                     //at TCP port 0
        Address.sin_addr.s_addr = inet_addr("0.0.0.0");
        strcpy(IPAddr, "0.0.0.0");
        RecordedLatency = 0;
        Active = false;                                 //Inactive, of course
        Address.sin_family = AF_INET;
    }
    Proxy(char* addr, int port)                         //The constructor with the IP address and TCP port
    {
        Address.sin_addr.s_addr = inet_addr(addr);
        strcpy(IPAddr, addr);
        Address.sin_port = htons(port);                 //Sets the address
        IPDoor = port;                                  //And port
        Active = false;                                 //and sets the proxy as inactive
        RecordedLatency = 0;
        Address.sin_family = AF_INET;
    }
    void ShowProxy()
    {
        cout << IPAddr << ":" << IPDoor << " with latency " << RecordedLatency << endl;
    }
    bool CheckProxy(OptArray* Opts)
    {   //The main method for the whole class, for this kind of program
        //The input is the options for the check, and the internal variables
        //The output is a boolean indicating whether the proxy is active or not.
        //Also, it sets the internal boolean variable "Active" accordingly.
        int SocketID,ConID;
        time_t start, finish;
        char RecievedData[20];
        //The received data buffer is only 20 bytes long because all we need to catch is the
        //"200 OK" HTTP code, anything else is out of the question as unusable.
        SocketID = socket(AF_INET,SOCK_STREAM,0);       //Setting the socket...
        if (SocketID == -1) {
            if (Options.Verbosity)  cerr << "[!] Error: Unable to set a socket.\n";
            Active = false;
            return false;
        }
        setsockopt(SocketID,SOL_SOCKET,SO_SNDTIMEO,&(Opts->Timeout),sizeof(Opts->Timeout));     //Setting the connection
        setsockopt(SocketID,SOL_SOCKET,SO_RCVTIMEO,&(Opts->Timeout),sizeof(Opts->Timeout));     //timeout values...
        time(&start);                                  //...and starting the timer for the latency calculation
        ConID = connect(SocketID, (sockaddr *) &Address, sizeof(Address));          //Connecting...
        if(ConID == -1){                                                            //If the connection fails,
            if (Options.Verbosity) cerr << "[!] Could not connect to proxy " << IPAddr << ":" << IPDoor << endl; //say so, and
            Active = false;                                                                         //set proxy as inactive
            return false;
        }
        bind(SocketID,(sockaddr *)&Address, sizeof(Address));                       //If connection succeeds,
        send(SocketID,Opts->Texttosend,Opts->SizeToSend,0);                         //send the data,
        recv(SocketID,RecievedData,18,0);                                           //capture the answer,
        shutdown(SocketID, 2);                                                      //and close the connection.
        close(SocketID);
        time(&finish);                                                              //Stop the timer
        RecordedLatency = (int) difftime(finish, start);                            //and calculate the latency
        if (RecordedLatency >= (int)Opts->Timeout.tv_sec) {                         //Checking for timeout
            if (Options.Verbosity) cerr << "[!] Error: Timeout for proxy " << IPAddr << ":" << IPDoor << endl; //if the latency is equal or greater
            Active = false;                                                         //than the specified timeout option
            return false;                                                           //the proxy is non-responsive aka inactive
        }
        if (!strncmp((RecievedData+9),"200",3) && Options.Verbosity){
            ShowProxy();
            cout << "Responded 200 OK" << endl;
        }
                                                //I must add a routine here to help identify the HTTP codes
        Active = true;                          //and determine if the server can be identified as active or not.
        return true;
    }
};


int main(int argc, char* argv[])
{
    Options.Timeout.tv_sec = 5;     //Default timeout values
    Options.Timeout.tv_usec = 0;    //5 second timeout
    int codeopt = 0, i=0;           //Utility variables
    char Text [120];                //The text to send to the proxy
    if(argc<2){
        cout << "Usage: " << argv[0] << " [OPTIONS] ADDRESS or " << argv[0] << " [OPTIONS] -f FILENAME" << endl;
        cout << "Enter " << argv[0] << " --help for all test options" << endl;
        return 0;
    }
    for(i=1;i<=(argc-1);i++){           //Begin parsing the options...
        if (!checkarg(NULL, argv[i],2)) {   //Check if the option is a number, aka IP address...
            strcpy(Options.IPAddress, argv[i++]);   //...write it...
            if (!checkarg(NULL, argv[i],2)) {       //...and check whether it has a port number after that
                Options.Door = atoi(argv[i]);
            }
            else
            {
                if (Options.Verbosity) cout << "\nNo TCP port specified, using default port 80..." << endl;
                Options.Door = 80;
            }
            continue;
        }
        if (*argv[i] == '-') {          //Parsing the various options and values
            codeopt = parser(argv[i]);
            switch (codeopt){
                case 1: Options.FileSwitch = true;
                        if (checkarg(argv[i],argv[(i<argc)?i+1:i],codeopt)) {cout << "\nMissing input file path.\n";return 2;}
                        strcpy(Options.FilePath, argv[++i]);
                        break;
                case 2: Options.TimeoutSwitch = true;
                        if (checkarg(argv[i],argv[(i<argc)?i+1:i],codeopt)) {cout << "\nMissing timeout (in seconds).\n";return 2;}
                        Options.Timeout.tv_sec = atoi(argv[++i]);
                        break;
                case 3: Options.OutputSwitch = true;
                        if (checkarg(argv[i],argv[(i<argc)?i+1:i],codeopt)) {cout << "\nMissing output file path.\n";return 2;}
                        strcpy(Options.OutputPath, argv[++i]);
                        break;
                case 4: Options.CheckSiteSwitch = true;
                        if (checkarg(argv[i],argv[(i<argc)?i+1:i],codeopt)) {cout << "\nMissing check website path.\n";return 2;}
                        strcpy(Options.CheckSite, argv[++i]);
                        httpstrip(&Options);                //Checking and normalizing the check site
                        break;
                case 5: help();
                        return 0;
                case 6: Options.Verbosity = false;
                        break;
                default:
                        cout << "\nInvalid switch:" << argv[i] << endl;
                        return 1;
            }
            continue;
        }
        cout << "Invalid argument" <<argv[i] << endl;
        cout << "Enter proxycheck --help for all test options" << endl;
        return 3;
    }
/*
    //Some debugging debris
    cout << "Out of the options\n";
    cout << "Options\nFile path :" << Options.FileSwitch << " " << Options.FilePath << endl;
    cout << "Time " << Options.TimeoutSwitch << " " << Options.Timeout.tv_sec << endl;
    cout << "Output " << Options.OutputSwitch << " " << Options.OutputPath << endl;
    cout << "Check " << Options.CheckSiteSwitch << " " << Options.CheckSite << endl;
    cout << "IP addr " << Options.IPAddress << " " << Options.Door << endl;
*/

    strcpy(Text, "GET http://");
    strcat(Text, Options.CheckSite);
    strcat(Text, "/ HTTP/1.1\n");
    strcat(Text, "Host: ");
    strcat(Text, Options.CheckSite);
    strcat(Text, "\n\n\0");
    /*
    Proxies usually require other headers too, to deliver the data
    such as the "Host" header
    GET http://www.secmaniac.com/ HTTP/1.1
    Host: www.secmaniac.com
    I'll need to re-think of the way the website string is handled
    and I'll need to check/test/experiment with the timeout options.
    */
    Options.Texttosend = Text;
    i=0;
    while(*(Text + i)!='\0'){i++;}
    Options.SizeToSend = i;
    if (Options.FileSwitch){    //Read proxies from a file and iterate through them
        FILE *infile;           //Pointer to the file being read
        char s, filetext [25];  //and utility variables
        infile = fopen(Options.FilePath, "r");
        if (infile == NULL) {   //If file doesn't open, throw error and exit.
            cout << "[!] Error opening the input file." << endl;
            return 2;
        }
        /*
        The file format must be a list of IP addresses and ports, separated by a space, tab or semicolon
        The following loop iterates through the file until an EOF is encountered.
        */
        while ((s = fgetc(infile) ) != EOF){
            //Sanity check if the character read is actually in the form required
            //That is, the char is either a number, a newline or a separation character
            if (checkarg(NULL,&s,2) && (s != ':') && (s != ' ') && (s != '\t') && (s != '\n') ) {
                cout << "[!] Error reading input file " << Options.FilePath << "." << endl;
                cout << "[!] Invalid character in file." << endl;
                return 3;
            }
            if ((s == '\t') || (s == ' ') || s == ':') {    //If a separation character is encountered
                strcpy(Options.IPAddress, filetext);        //Copy the text read to the IP Address
                for(i=0;i<26;i++){filetext[i] = '\0';}      //and clear the file text string
                continue;
            }
            if (s == '\n'){                                 //If a newline character is encountered
                if (filetext[7] == '\0') {                  //And the string has been cleared, aka there was an IP address before
                    Options.Door = atoi(filetext);          //the text in the filetext string is the port, and is copied
                }
                else
                {
                    Options.Door = 80;                      //Otherwise the default port 80 is copied
                }
                for(i=0;i<26;i++){filetext[i] = '\0';}      //And the string is cleared
                Proxy test(Options.IPAddress, Options.Door);//The Proxy object is made, in the scope of the if block
                if(test.CheckProxy(&Options)) {             //Runs the typical check, and we're off
                    if (Options.Verbosity) cout << "[i] Proxy active and running!" << endl;
                    if (Options.OutputSwitch) {
                        cout << "Output to file not yet supported." << endl;
                        //Write to file the output of the check.
                    }
                }
                continue;
            }
            strcat(filetext, &s);                           //If the read char is of no significance, just append it to the filetext string
        }
        return 0;
    }

    Proxy test(Options.IPAddress, Options.Door);
    if(test.CheckProxy(&Options)) {
        if (Options.Verbosity) cout << "[i] Proxy active and running!" << endl;
        if (Options.OutputSwitch) {
            cout << "Output to file not yet supported." << endl;
            //Write to file the output of the check.
            return 0;
        }
    }
    //test.ShowProxy();


    return 0;
}
