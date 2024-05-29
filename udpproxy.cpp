/**
 * 2017.
 * Only ipv4
 * Single threaded!
 * if you use SO_REUSEPORT, you must have a dedicated user account.
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <sstream>
#include <string>
#include <map>
#include <cstring>
#include <iomanip>
#include <signal.h>
#include <cerrno>
#include <sys/time.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <cstdio>
#include <unistd.h>
#include <sys/epoll.h>

using namespace std;

namespace {

// Mappings
struct value {
    int32_t fd;
    struct sockaddr_in addr;
};

using statsMap = map<uint64_t, uint64_t>;
uint64_t g_USEFDS = 1000;
uint32_t g_RECV_BUFFER_SIZE = 1024l * 1024 * 6;
uint32_t g_SND_BUFFER_SIZE = 1024l * 1024 * 6;
uint16_t g_interval = 5; // Minutes
volatile bool g_clearConnectionMap = false;
volatile bool g_verboseDebug = false;
volatile bool g_shutdown = false;
volatile bool g_alarm = false;
bool g_verboseStatistics = false;
bool g_dumpPacketAscii = false;
bool g_dumpPacketHex = false;
bool g_REUSEPORT = false;

string timestamp() {
    struct timeval tv;
    time_t nowtime;
    struct tm *nowtm;
    char tmbuf[32], buff[64];

    ::gettimeofday(&tv, NULL);
    nowtime = tv.tv_sec;
    nowtm = ::localtime(&nowtime);
    ::strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%d %H:%M:%S", nowtm);
    ::snprintf(buff, sizeof(buff), "%s.%06ld", tmbuf, tv.tv_usec);
    return buff;
}

string errnoStr() {
    if (errno == 0)
        return "-";
    char * e = ::strerror(errno);
    return e ? e : "-";
}

void printError(string const &str) {
    cout << timestamp() << " ERROR  " << str << " (" << errno << ":" << errnoStr() << ")" << endl;
}

void printErrorAndClearERRNO(string const &str) {
    printError(str);
    errno = 0;
}

void printInfo(string const &str) {
    cout << timestamp() << " INFO   " << str << endl;
}

void printDebug(string const &str) {
    cout << timestamp() << " DEBUG  " << str << endl;
}

vector<string>::iterator findCmdOption(vector<string> &v, string const & option) {
    return find(v.begin(), v.end(), option);
}

uint64_t checkAndAdjustMaxUsableFds(uint64_t fdsToUse) {
    struct rlimit rl;
    ::getrlimit(RLIMIT_NOFILE, &rl);
    if (fdsToUse > rl.rlim_max) {
        stringstream ss;
        ss << "Max FDS(" << fdsToUse << ") greater then rlim_max(" << rl.rlim_max
                << ")!  Cry out for an admin ;-)";
        printError(ss.str());
    }
    uint64_t old_cur = rl.rlim_cur;
    if (fdsToUse > rl.rlim_cur) {
        rl.rlim_cur = fdsToUse;
        int32_t error = ::setrlimit(RLIMIT_NOFILE, &rl);
        stringstream ss;
        if (error == 0) {
            ss << "Setting RLIMIT_NOFILE to = " << rl.rlim_cur;
            printInfo(ss.str());
        } else {
            ss << "Setting RLIMIT_NOFILE to = " << rl.rlim_cur << " FAILED!";
            printErrorAndClearERRNO(ss.str());
            if (rl.rlim_max > old_cur) {
                rl.rlim_cur = rl.rlim_max;
                error = ::setrlimit(RLIMIT_NOFILE, &rl);
                stringstream ss;
                if (error == 0) {
                    ss << "Setting RLIMIT_NOFILE to = " << rl.rlim_cur;
                    printInfo(ss.str());
                } else {
                    ss << "Setting RLIMIT_NOFILE to = " << rl.rlim_cur << " FAILED!";
                    printErrorAndClearERRNO(ss.str());
                }
            }
        }
    }
    return rl.rlim_cur;
}

void printRLimits() {
    struct rlimit rl;
    stringstream ss;
    ::getrlimit(RLIMIT_CPU, &rl);
    ss << "CPU  ]  cur: " << rl.rlim_cur << "  max:" << rl.rlim_max << "   seconds";
    printInfo(ss.str());
    ss.str("");
    ::getrlimit(RLIMIT_STACK, &rl);
    ss << "STACK]  cur: " << rl.rlim_cur << "  max:" << rl.rlim_max << "   kbytes";
    printInfo(ss.str());
    ss.str("");
    ::getrlimit(RLIMIT_NOFILE, &rl);
    ss << "FDs  ]  cur: " << rl.rlim_cur << "  max:" << rl.rlim_max << "   count";
    printInfo(ss.str());
}

// return 0 in case of failure or
// ipv4 address as int32_t in network order
uint32_t hostnameToIpV4(string const &hostname, string &dottedIP) {
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_in *h;

    ::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = 0;
    int32_t rv;
    if ((rv = ::getaddrinfo(hostname.c_str(), NULL, &hints, &servinfo)) != 0) {
        stringstream ss;
        ss << "hostname_to_ip_ipv4 failed: " << ::gai_strerror(rv);
        printErrorAndClearERRNO(ss.str());
        return 0;
    }
    p = servinfo;
    uint32_t a = 0;

    // loop
    while (p) {
        // paranoia check
        if (p->ai_family != AF_INET6) {
            h = (struct sockaddr_in *) p->ai_addr;
            dottedIP = ::inet_ntoa(h->sin_addr);
            a = h->sin_addr.s_addr;
            goto EXIT;
        }
        p = p->ai_next;
    }

    EXIT: ::freeaddrinfo(servinfo);
    return a;
}

void signalHandler(int sigNumber) {
    switch (sigNumber) {
    case SIGHUP: // 1
        if (g_clearConnectionMap == false)
            g_clearConnectionMap = true;
        break;
    case SIGFPE: // 8
        g_verboseDebug = !g_verboseDebug;
        break;
    case SIGUSR1: // 10
           // any use ?
        break;
    case SIGALRM: // 14
        if (g_alarm == false)
            g_alarm = true;
        break;
    case SIGTERM: // 15
        g_shutdown = true;
        break;
    default:
        return;
    }
}

string ipv4Address(uint32_t nIP) {
    char _buff[32];
    inet_ntop(AF_INET, &nIP, _buff, 32);
    return _buff;
}

struct concat {
    concat(string &ref)
            : _ref(ref) {
    }
    void operator()(string const &in) {
        _ref += " ";
        _ref += in;
    }
    string &_ref;
};


static void closeFDs(std::pair<const int32_t, map<uint64_t, value>::iterator> &pair)
{
    int32_t err = ::close(pair.first);
    if (err != 0)
        printErrorAndClearERRNO("close failed");
}

template<class T> T fromString(string const &s) {
    istringstream stream(s);
    T t;
    stream >> t;
    return t;
}

template<class T> string toString(T value) {
    stringstream ss;
    ss << value;
    return ss.str();
}

// sets some global variables
void populateEnv() {
    char * _fds = ::getenv("UDPPROXY_USEFDS");
    if (_fds != NULL) {
        string _temp_fds(_fds);
        uint32_t _temp_num = fromString<uint32_t>(_temp_fds);
        if (_temp_num != 0) {
            g_USEFDS = _temp_num;
            stringstream ss;
            ss << "Setting max to use FDS to " << g_USEFDS;
            printInfo(ss.str());
        }
    }

    char * _recbuf = ::getenv("UDPPROXY_RECBUF");
    if (_recbuf != NULL) {
        string _temp_str(_recbuf);
        int32_t _temp_num = fromString<int32_t>(_temp_str);
        if (_temp_num >= 0) {
            g_RECV_BUFFER_SIZE = _temp_num;
            stringstream ss;
            ss << "Setting RECV_BUFFER_SIZE to " << g_RECV_BUFFER_SIZE;
            printInfo(ss.str());
        }
    }

    char * _sndbuf = ::getenv("UDPPROXY_SNDBUF");
    if (_sndbuf != NULL) {
        string _temp_str(_sndbuf);
        int32_t _temp_num = fromString<int32_t>(_temp_str);
        if (_temp_num >= 0) {
            g_SND_BUFFER_SIZE = _temp_num;
            stringstream ss;
            ss << "Setting SND_BUFFER_SIZEE to " << g_SND_BUFFER_SIZE;
            printInfo(ss.str());
        }
    }

    char * _reuse = ::getenv("UDPPROXY_REUSEPORT");
    if (_reuse != NULL) {
        g_REUSEPORT = true;
        printInfo("Setting REUSEPORT to true");
    }

    char * _interval = ::getenv("UDPPROXY_TIMER_INTERVAL");
    if (_interval != NULL) {
        int64_t _temp_num = fromString<int64_t>(_interval);
        if (_temp_num >= 1 && _temp_num <= 1440 /*24h*/) {
            g_interval = _temp_num;
            printInfo("Setting UDPPROXY_TIMER_INTERVAL to " + toString(_temp_num));
        } else {
            printError("UDPPROXY_TIMER_INTERVAL not in range: " + toString(_temp_num) + " Using default");
        }
    }
}

// ascii dump.. in parenthesis decimal number of character
void packetDumpAscii(void * buffer, uint64_t size, stringstream &ss, char escape = (char) 0xF7) {
    unsigned char const * _start_ = static_cast<unsigned const char*>(buffer);
    for (uint32_t i = 0; i < size; i++) {
        unsigned char c = *(_start_ + i);
        if (c < 32 || c > 126)
            ss << escape << (unsigned int) c << escape;
        else
            ss << c;
    }
}

// hex dump.. ss is clear
string packetDumpHex(void * buffer, uint64_t size) {
    unsigned char const * _start_ = static_cast<unsigned const char*>(buffer);
    std::stringstream ss;
    ss << uppercase << right << setw(2) << setfill('0') << hex;
    for (uint32_t i = 0; i < size; i++) {
        uint32_t c = *(_start_ + i);
        ss << c;
    }
    return ss.str();
}

void checkPortRange(int32_t port, string const &addr) {
    if (port > 0 && port <= 0xFFFF) {
        // okay
    } else {
        stringstream ss;
        ss << "!!! Not a valid port range(" << port << ") for address  " << addr;
        printError(ss.str());
        ::exit(4);
    }
}

bool setSocketNonBlocking(int sfd) {
    int32_t flags, s;

    flags = ::fcntl(sfd, F_GETFL, 0);
    if (flags == -1) {
        printErrorAndClearERRNO("makeSocketNonBlocking");
        return false;
    }

    flags |= O_NONBLOCK;
    s = fcntl(sfd, F_SETFL, flags);
    if (s == -1) {
        printErrorAndClearERRNO("makeSocketNonBlocking");
        return false;
    }

    return true;
}

string getPeerName(uint32_t socket) {
    struct sockaddr_in temp;
    socklen_t ts = sizeof(sockaddr_in);
    if (::getpeername(socket, (struct sockaddr *) &temp, &ts) == 0) {
        stringstream ss;
        ss << ipv4Address(temp.sin_addr.s_addr) << ":" << ntohs(temp.sin_port);
        return ss.str();
    } else {
        printErrorAndClearERRNO("getpeername() failed");
    }
    return "-:-";
}

struct sockaddr_in getPeerAddr(uint32_t socket) {
    struct sockaddr_in temp;
    socklen_t ts = sizeof(sockaddr_in);
    if (::getpeername(socket, (struct sockaddr *) &temp, &ts) == 0) {
        return temp;
    } else {
        printErrorAndClearERRNO("getPeerAddr() failed");
    }
    memset(&temp, 0, sizeof(temp));
    return temp;
}

void applySocketBuffer(uint32_t fd, uint32_t sendSize, uint32_t recvSize) {
    int32_t error = 0;
    if (recvSize != 0) {
        int32_t RECV_BUFFER_SIZE = recvSize;
        error = ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &RECV_BUFFER_SIZE, sizeof(RECV_BUFFER_SIZE));
        if (error != 0) {
            stringstream ss;
            ss << "Couldn't set SO_RCVBUF to " << RECV_BUFFER_SIZE << " FD=" << fd;
            printErrorAndClearERRNO(ss.str());
        }
    } else {
        printInfo("RECV_BUFFER_SIZE set to zero. Let the kernel handle it. FD=" + toString(fd));
    }

    if (sendSize != 0) {
        int32_t SND_BUFFER_SIZE = sendSize;
        error = ::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &SND_BUFFER_SIZE, sizeof(SND_BUFFER_SIZE));
        if (error != 0) {
            stringstream ss;
            ss << "Couldn't set SO_SNDBUF to " << SND_BUFFER_SIZE << " FD=" << fd;
            printErrorAndClearERRNO(ss.str());
        }
    } else {
        printInfo("SND_BUFFER_SIZE set to zero. Let the kernel handle it. FD=" + toString(fd));
    }
}

void setRecurringTimer(uint16_t minutes) {
    struct itimerval timer;
    timer.it_value.tv_sec = ((uint32_t) minutes) * 60;
    timer.it_value.tv_usec = 0;
    timer.it_interval.tv_sec = ((uint32_t) minutes) * 60;
    timer.it_interval.tv_usec = 0;
    if (::setitimer(ITIMER_REAL, &timer, NULL) != 0) {
        printErrorAndClearERRNO("setitimer failed for timeout=" + toString(minutes) + " minutes.");
        ::exit(8);
    }
}

int32_t createUDPSocket() {
    int32_t fd = ::socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (fd == -1) {
        printErrorAndClearERRNO("Couldn't create listen socket");
        ::exit(10);
    }
    return fd;
}

inline uint64_t makeKey(struct sockaddr_in const &addr) {
    uint64_t __ = (uint64_t) addr.sin_addr.s_addr << 16;
    __ += addr.sin_port;
    return __;
}

string makeAddr(uint64_t key) {
    uint32_t ip = (key >> 16) & (uint64_t) 0xFFFFFFFF;
    uint16_t port = key & 0xFFFF;
    stringstream ss;
    ss << ipv4Address(ip) << ":" << ntohs(port);
    return ss.str();
}

string formatAddr(uint64_t key) {
    stringstream ss;
    uint32_t ip = (key >> 16) & (uint64_t) 0xFFFFFFFF;
    uint16_t port = key & 0xFFFF;
    ss << left << setfill(' ') << setw(15) << ipv4Address(ip) << " : " << right << setfill(' ') << setw(5)
            << ntohs(port);
    return ss.str();
}

void printStatsAndClear(uint64_t &packetsReceived, uint64_t &packetsSend, statsMap &recvStats, statsMap &sndStats, string const& prolog) {
    stringstream ss;
    ss << prolog << packetsReceived << " packets received since last message\n";

    //sendingPart receiving part
    statsMap::const_iterator iter = recvStats.begin();
    statsMap::const_iterator end = recvStats.end();
    if (g_verboseStatistics) {
        ss << prolog << left << setw(23) << setfill(' ') << "        IP : Port" << "  |  " << " Bytes received\n";
        ss << prolog << left << setw(23) << setfill('-') << "---------------" << "--+--" << "----------------\n";
        while (iter != end) {
            ss << prolog << left << setw(22) << setfill(' ') << formatAddr((*iter).first) << "  |  " << right << setw(15)
                    << setfill(' ') << (*iter).second << "\n";
            ++iter;
        }
        recvStats.clear();
    }
    //sending Part
    ss  << prolog << packetsSend << " packets send since last message\n";
    if (g_verboseStatistics) {
        iter = sndStats.begin();
        end = sndStats.end();
        ss << prolog << left << setw(23) << setfill(' ') << "        IP : Port" << "  |  " << "   Bytes send\n";
        ss << prolog << left << setw(23) << setfill('-') << "---------------" << "--+--" << "----------------\n";
        while (iter != end) {
            ss << prolog << left << setw(22) << setfill(' ') << formatAddr((*iter).first) << "  |  " << right << setw(15)
                    << setfill(' ') << (*iter).second  << "\n";
            ++iter;
        }
        sndStats.clear();
    }
    // dump stats
    cout << ss.str() << flush;

    packetsReceived = 0;
    packetsSend = 0;
}

void bindListenSocket(int32_t listenFD, uint32_t sourceIPNetwork, uint16_t listenPort) {
    struct sockaddr_in lsock;
    lsock.sin_family = AF_INET;
    lsock.sin_addr.s_addr = sourceIPNetwork;
    lsock.sin_port = htons(listenPort);
    if (::bind(listenFD, (struct sockaddr*) (&lsock), sizeof(lsock)) == -1) {
        stringstream ss;
        ss << "Listen: Can't bind to address ('" << ipv4Address(sourceIPNetwork) << ":" << listenPort << "')";
        printErrorAndClearERRNO(ss.str());
        ::exit(6);
    }
}

bool bindAndConnectToTarget(int32_t _newFD, uint32_t sourceToTargeIPNetwork, uint16_t targetPort,
        uint32_t targetIPNetwork) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = sourceToTargeIPNetwork;
    addr.sin_port = 0;
    if (::bind(_newFD, (struct sockaddr*) (&addr), sizeof(addr)) == -1) {
        stringstream ss;
        ss << "Listen: Can't bind to address ('" << ipv4Address(addr.sin_addr.s_addr) << ":" << addr.sin_port << "')";
        printErrorAndClearERRNO(ss.str());
        return false;
    }

    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = targetIPNetwork;
    target.sin_port = htons(targetPort);

    // connect() call to get some icmp messages back..more errors
    int32_t _err = ::connect(_newFD, (struct sockaddr *) &target, sizeof(target));
    if (_err != 0) {
        stringstream ss;
        ss << "Connect failed " << ipv4Address(target.sin_addr.s_addr) << ":" << targetPort;
        printErrorAndClearERRNO(ss.str());
        return false;
    }
    return true;
}

int32_t getSocketError(int32_t fd) {
    int32_t error = 0;
    socklen_t errlen = sizeof(error);
    if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *) &error, &errlen) == 0) {
        return error;
    }
    return 0;
}

string getSockName(int32_t fd) {
    struct sockaddr_in addr;
    socklen_t addrSize = sizeof(addr);
    if (::getsockname(fd, (struct sockaddr *) &addr, &addrSize) != 0) {
        printErrorAndClearERRNO("getsockname() failed!!");
        return "-:-";
    } else {
        stringstream ss;
        ss << ipv4Address(addr.sin_addr.s_addr) << ":" << ntohs(addr.sin_port);
        return ss.str();
    }
}

void clearConnectionMap(map<uint64_t, value> &keyToAddrAndFd, map<int32_t, map<uint64_t, value>::iterator> &fdToIter) {

    for_each(fdToIter.begin(), fdToIter.end(), closeFDs);
    keyToAddrAndFd.clear();
    fdToIter.clear();
}

} // namespace end

static void epollAll(uint32_t sourceIPNetwork, uint16_t listenPort, uint16_t targetPort, uint32_t targetIPNetwork, uint32_t sourceToTargeIPNetwork) {
    int32_t listenFD = createUDPSocket();

    bool ok = setSocketNonBlocking(listenFD);
    if (!ok) {
        printError("Couldn't set listen socket to non blocking");
        ::exit(100);
    }

    applySocketBuffer(listenFD, g_SND_BUFFER_SIZE, g_RECV_BUFFER_SIZE);

    // Listen socket
    bindListenSocket(listenFD, sourceIPNetwork, listenPort);

    int32_t efd = ::epoll_create1(0);
    if (efd == -1) {
        printError("epoll_create1 failed");
        ::exit(101);
    }

    struct epoll_event event;
    event.data.fd = listenFD;
    event.events = EPOLLIN;
    int32_t err = ::epoll_ctl(efd, EPOLL_CTL_ADD, listenFD, &event);
    if (err == -1) {
        printError("epoll_ctl failed");
        ::exit(101);
    }

    // event buffer
    struct epoll_event *events;
    events = new (nothrow) epoll_event[g_USEFDS];
    if (events == NULL) {
        // restart System!!!
        cerr << "!!!  Out of memory  !!!";
        ::exit(255);
    }

    map<uint64_t, value> keyToAddrAndFd;

    map<int32_t, map<uint64_t, value>::iterator> fdToIter;

    const uint16_t BUFF_SIZE = 0xFFFF;
    //16 bytes aligned?
    void * buf = new (nothrow) char[BUFF_SIZE];
    if (buf == NULL) {
        // restart System!!!
        cerr << "!!!  Out of memory  !!!";
        ::exit(255);
    }

    uint64_t packetsReceived = 0;
    uint64_t packetsSend = 0;
    statsMap recvStats;
    statsMap sndStats;

    /*
     * The event loop
     */
    const int32_t FOR_EVER = -1;
    while (!g_shutdown) {
        int32_t nr = ::epoll_wait(efd, events, g_USEFDS, FOR_EVER);
        if (g_verboseDebug)
        {
            if (g_alarm)
                printDebug("Alarm signal received.");
            if (g_clearConnectionMap)
                printDebug("SIGHUP signal received.");
        }
        // received signal?
        if (g_alarm || g_clearConnectionMap) {
            stringstream ss;
            string ts = timestamp();
            ss << ts << " INFO   ";
            string prolog = ss.str();
            ss.str("");
            ss << prolog << "Size of sendMap        = " << sndStats.size() << "  Size of receiveMap = " << recvStats.size() << "\n";
            ss << prolog << "Size of keyToAddrAndFd = " << keyToAddrAndFd.size() << "  Size of fdToIter   = " << fdToIter.size() << "\n";
            cout << ss.str();

            printStatsAndClear(packetsReceived, packetsSend, recvStats, sndStats, prolog);
            if (g_alarm)
                g_alarm = false;
            if (g_clearConnectionMap) {
                clearConnectionMap(keyToAddrAndFd, fdToIter);
                g_clearConnectionMap = false;
            }
        }
        
     
        for (int32_t i = 0; i < nr; i++) {
            if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN))) {
                int32_t _fd = events[i].data.fd;
                errno = getSocketError(_fd);
                printErrorAndClearERRNO("epoll_wait: " + makeAddr((*fdToIter[_fd]).first) );

                if (listenFD == events[i].data.fd) {
                    printError("Weird things are happening...");
                    continue;
                }

                int32_t err = ::close(_fd);
                if (err != 0)
                    printErrorAndClearERRNO("close failed");


                // delete from mappings
                keyToAddrAndFd.erase(fdToIter[_fd]);
                fdToIter.erase(_fd);
                continue;
            }

            else if (listenFD == events[i].data.fd) {
                // traffic at listen side
                struct sockaddr_in othersideAddr;
                socklen_t othersideAddrSize = sizeof(othersideAddr);

                ssize_t n = ::recvfrom(listenFD, buf, BUFF_SIZE, 0, (struct sockaddr *) &othersideAddr, &othersideAddrSize);
                if (n <= 0) {
                    // fuck ????
                    printErrorAndClearERRNO("recvfrom on listen side failed ???? !");
                    continue;
                }

                if (g_verboseStatistics) {
                    uint64_t &counter = recvStats[makeKey(othersideAddr)];
                    counter += n;
                }
                packetsReceived++;

                uint64_t key = makeKey(othersideAddr);
                struct value & _v = keyToAddrAndFd[key];
                if (_v.fd == 0) {
                    // first check the ranges
                    if(keyToAddrAndFd.size() >= (g_USEFDS-4) ) {
                        printError("ConnectionsMap to big: " + toString(g_USEFDS-4) + " Clearing...");
                        clearConnectionMap(keyToAddrAndFd, fdToIter);
                    }
                    // new client...create mapping and a distinct socket to target.
                    _v.addr = othersideAddr;
                    int32_t _newFD = createUDPSocket();
                    setSocketNonBlocking(_newFD);
                    _v.fd = _newFD;
                    bindAndConnectToTarget(_newFD, sourceToTargeIPNetwork, targetPort, targetIPNetwork);
                    fdToIter[_newFD] = keyToAddrAndFd.find(key);
                    struct epoll_event _event;
                    _event.data.fd = _newFD;
                    _event.events = EPOLLIN;
                    int32_t _err = epoll_ctl(efd, EPOLL_CTL_ADD, _newFD, &_event);
                    if (_err == -1)
                        printError("epoll_ctl failed for a new connection..??? ignoring");

                    stringstream ss;
                    ss << "connect client: " << makeAddr(key) << " via: " << getSockName(_newFD) << " to: " << getPeerName(_newFD);
                    printInfo(ss.str());
                }

                if (g_verboseDebug) {
                    stringstream ss;
                    ss.str("");
                    string recvIP(ipv4Address(_v.addr.sin_addr.s_addr));
                    recvIP += ":";
                    recvIP += toString(ntohs(_v.addr.sin_port));
                    ss << "Packet received from: " << recvIP << " size: " << n << " on listen addr";
                    printDebug(ss.str());
                    if (g_dumpPacketAscii) {
                        ss.str("");
                        ss << recvIP << " Ascii-Data: ";
                        packetDumpAscii(buf, n, ss);
                        printDebug(ss.str());
                    }
                    if (g_dumpPacketHex) {
                        ss.str("");
                        ss << recvIP << " Hex-Data  : " << packetDumpHex(buf, n);
                        printDebug(ss.str());
                    }
                }

                // send it to dest via special socket
                ssize_t rV = ::send(_v.fd, buf, n, 0);
                //error!
                if (rV == -1) {
                    stringstream ss;
                    string _trg = getPeerName(_v.fd);
                    string _src = getSockName(_v.fd);
                    ss << "send() to " << _trg << "  from " << _src << " ! Packet lost.";
                    printErrorAndClearERRNO(ss.str());
                } else if (g_verboseDebug) {
                    stringstream ss;
                    string _trg = getPeerName(_v.fd);
                    string _src = getSockName(_v.fd);
                    ss << "Packet send to: " << _trg << " size: " << rV << "  via " << _src;
                    printDebug(ss.str());
                }
                if (rV != -1) {
                    if (g_verboseStatistics) {
                        uint64_t &counter = sndStats[makeKey(getPeerAddr(_v.fd))];
                        counter += rV;
                    }
                    packetsSend++;
                }

            } else {
                // So we have activity on the registerd epoll fds
                int32_t connectedSocket = events[i].data.fd;
                struct value _v = (*fdToIter[connectedSocket]).second;

                ssize_t _nr = ::recv(connectedSocket, buf, BUFF_SIZE, 0);
                if (_nr < 0) {
                    stringstream ss;
                    ss << "Non blocking recv() failed for " << getPeerName(connectedSocket) << "  .Packet lost.";
                    printErrorAndClearERRNO(ss.str());
                    // ? ? ?
                    continue;
                }
                packetsReceived++;

                // try to send to client on listening side
                ssize_t _error = sendto(listenFD, buf, _nr, 0, (struct sockaddr*) &(_v.addr), sizeof(_v.addr));
                if (_error < 0) {
                    printErrorAndClearERRNO("sendto client on listening side failed! Packet lost.");
                    // ? ? ?
                    continue;
                }
                packetsSend++;

                if (g_verboseStatistics) {
                    uint64_t &counter = recvStats[makeKey(getPeerAddr(connectedSocket))];
                    counter += _nr;

                    uint64_t &_scounter = sndStats[makeKey(_v.addr)];
                    _scounter += _error;
                }

                if (g_verboseDebug) {
                    stringstream ss;
                    ss.str("");
                    string sndIP(ipv4Address(_v.addr.sin_addr.s_addr));
                    sndIP += ":";
                    sndIP += toString(ntohs(_v.addr.sin_port));
                    ss << "Packet received from: " << getPeerName(connectedSocket) << " size: " << _nr
                            << " and sendto: " << sndIP;
                    printDebug(ss.str());
                    if (g_dumpPacketAscii) {
                        ss.str("");
                        ss << getPeerName(connectedSocket) << " Ascii-Data: ";
                        packetDumpAscii(buf, _nr, ss);
                        printDebug(ss.str());
                    }
                    if (g_dumpPacketHex) {
                        ss.str("");
                        ss << getPeerName(connectedSocket) << " Hex-Data  : " << packetDumpHex(buf, _nr);
                        printDebug(ss.str());
                    }
                }
            }
        }
    }

    // events will be delete from os
    // sockets will be closed from os

}

/////////////
//
// M A I N
//
/////////////
int main(int argc, char *argv[]) {
    // no C i/o allowed
    ios_base::sync_with_stdio(false);

    // untie cin from cout
    cin.tie(NULL);

    stringstream ss;

    // check commandline argument
    vector<string> cmdArgs(argv + 1, argv + argc);
    vector<string>::iterator opt;

    //help
    opt = findCmdOption(cmdArgs, "-h");
    if (opt != cmdArgs.end()) {
        char c = (char) 0xF7;
        cerr << "Frank Peters 09.2017 to survive a requirement\n"
                << "Single threaded and only for IPv4 and no security\n" << argv[0]
                << " listenAddress targetAddress \n" 
                << "-h             this help \n"
                << "-v             more verbose(DEBUG) output\n" 
                << "-s             detailed statistics\n"
                << "-va            as -v plus ascii packet dump. E.g.: ICH BINS" << c << "10" << c << ". " << c << "10"
                << c << "=New line. " << c << "(0xF7)=Escape char\n"
                << "-vh            as -v plus hex packet dump. E.g.: AABBCCDDEEFF\n"
                << "-b             bind to specific source to use for target communication\n"
                << "listenAddress  IP(or name) and port to listen on. localhost:1234 \n"
                << "targetAddress  IP(or name) and port to forward traffic to. 123.123.123.1:6666 \n" << " Signals:\n"
                << "     SIGHUP    clear connection tracking table\n"
                << "     SIGALRM   print statistic\n"
                << " ENVIRONMENT\n" 
                << "     UDPPROXY_USEFDS            number of fds to use(1000)\n"
                << "     UDPPROXY_RECBUF            receive buffer size(6MB). Set to 0 to let the kernel decide\n"
                << "     UDPPROXY_SNDBUF            send buffer size(6MB).. Set to 0 to let the kernel decide\n"
                << "     UDPPROXY_REUSEPORT         anything means yes(false)\n"
                << "     UDPPROXY_TIMER_INTERVAL    interval to print stats in minutes(5). Range 1-1440\n"
                << "E.g:\n" << "UDPPROXY_USEFDS=9999 UDPPROXY_REUSEPORT=true " << argv[0] << " localhost:1025 localhost:1026 -v -s\n" << flush;
        ::exit(1);
    }

    string _str;

    for_each(cmdArgs.begin(), cmdArgs.end(), concat(_str));
    ss << "Starting " << argv[0] << "(" << ::getpid() << ") with command line arguments:" << _str;
    printInfo(ss.str());

    populateEnv();

    // Verbose plus packet dump ascii
    opt = findCmdOption(cmdArgs, "-va");
    if (opt != cmdArgs.end()) {
        g_verboseDebug = true;
        g_dumpPacketAscii = true;
        cmdArgs.erase(opt);
    }

    // Verbose plus packet dump hex
    opt = findCmdOption(cmdArgs, "-vh");
    if (opt != cmdArgs.end()) {
        g_verboseDebug = true;
        g_dumpPacketHex = true;
        cmdArgs.erase(opt);
    }

    // Verbose
    opt = findCmdOption(cmdArgs, "-v");
    if (opt != cmdArgs.end()) {
        g_verboseDebug = true;
        cmdArgs.erase(opt);
    }

    // Verbose stats
    opt = findCmdOption(cmdArgs, "-s");
    if (opt != cmdArgs.end()) {
        g_verboseStatistics = true;
        cmdArgs.erase(opt);
    }

    // bind source
    int32_t sourceToTargetPort = 0;
    string sourceToTargetHost = "";
    uint32_t sourceToTargeIPNetwork = 0;
    opt = findCmdOption(cmdArgs, "-b");
    if (opt != cmdArgs.end()) {
        vector<string>::iterator str = cmdArgs.erase(opt);
        if (str == cmdArgs.end()) {
            printError("No address given for -b...ignoring");
        } else {
            string addr = *str;
            cmdArgs.erase(str);
            stringstream ss;

            size_t portPos = addr.find(':');
            if (portPos == string::npos) {
                ss << "No Port given for " << addr << " using random one";
                printInfo(ss.str());
                string __;
                sourceToTargeIPNetwork = hostnameToIpV4(addr, __);
                if (sourceToTargeIPNetwork == 0 || sourceToTargeIPNetwork == 0xFFFFFFFF) {
                    printError("!!! sourceToTargetHost address (" + addr + ") not known !!!");
                    ::exit(4);
                }
            } else {
                string __ = addr.substr(portPos + 1);
                sourceToTargetPort = fromString<int32_t>(__);
                checkPortRange(sourceToTargetPort, addr);
                sourceToTargetHost = addr.substr(0, portPos);
                sourceToTargeIPNetwork = hostnameToIpV4(sourceToTargetHost, __);
                if (sourceToTargeIPNetwork == 0 || sourceToTargeIPNetwork == 0xFFFFFFFF) {
                    printError("!!! sourceToTargetHost address (" + addr + ") not known !!!");
                    ::exit(4);
                }
            }
        }
    }

    printRLimits();
    g_USEFDS = checkAndAdjustMaxUsableFds(g_USEFDS);
    if (g_USEFDS < 10 || g_USEFDS > 0xFFFFFFFF) {
        ss.str("");
        ss << "USEFDS outside limit (10-0xFFFFFFFF) : " << g_USEFDS;
        printError(ss.str());
        ::exit(4);
    }

    if (cmdArgs.size() != 2) {
        ss.str("");
        ss << "Wrong list of arguments!   " << "call " << argv[0] << " -h for help";
        printError(ss.str());
        ::exit(2);
    }

    /**
     * LISTEN
     */
    string listenHost = cmdArgs[0];
    uint32_t listenPort = 0;
    size_t portPos = listenHost.find(':');
    if (portPos != string::npos) {
        string __ = listenHost.substr(portPos + 1);
        listenPort = fromString<int>(__);
        listenHost = listenHost.substr(0, portPos);
    } else {
        printError("!!! Listen address in wrong format(" + listenHost + ") !!!   Example: ccc543.devlab.de.tmo:4711 ");
        ::exit(4);
    }
    if (listenPort == 0 || listenPort >= 0xFFFF) {
        printError(
                "!!! Listen address in wrong format(" + cmdArgs[0]
                        + "). Port wrong !!!   Example: ccc543.devlab.de.tmo:4711 ");
        ::exit(4);
    }

    /**
     * TARGET
     */
    string targetHost = cmdArgs[1];
    int32_t targetPort = 0;
    portPos = targetHost.find(':');
    if (portPos != string::npos) {
        string __ = targetHost.substr(portPos + 1);
        targetPort = fromString<int>(__);
        targetHost = targetHost.substr(0, portPos);
    } else {
        printError("!!! Target address in wrong format(" + targetHost + ") !!!   Example: ccc123.devlab.de.tmo:4711 ");
        ::exit(5);
    }
    if (targetPort == 0 || targetPort >= 0xFFFF) {
        printError(
                "!!! Target address in wrong format(" + cmdArgs[1]
                        + "). Port wrong !!!   Example: ccc123.devlab.de.tmo:4711 ");
        ::exit(5);
    }

    /*
     * Check for known/valid hostnames
     */
    string sourceIPDotted;
    string targetIPDotted;
    uint32_t sourceIPNetwork = 0;
    uint32_t targetIPNetwork = 0;
    sourceIPNetwork = hostnameToIpV4(listenHost, sourceIPDotted);
    targetIPNetwork = hostnameToIpV4(targetHost, targetIPDotted);
    if (sourceIPNetwork == 0 || sourceIPNetwork == 0xFFFFFFFF) {
        printError("!!! Source IP not valid(" + listenHost + ") !!!   Example: localhost");
        ::exit(6);
    }
    if (targetIPNetwork == 0 || targetIPNetwork == 0xFFFFFFFF) {
        printError("!!! target IP not valid(" + targetHost + ") !!!   Example: localhost");
        ::exit(7);
    }

    /**
     *  print info
     */
    ss.str("");
    string arrow = " <->";
    ss << "listenAddr: " << listenHost << "(" << sourceIPDotted << "):" << listenPort << arrow << " targetAddr: "
            << targetHost << "(" << targetIPDotted << "):" << targetPort;
    printInfo(ss.str());

    /**
     * set signal handlers
     */
    struct sigaction signal;
    signal.sa_handler = signalHandler;
    ::sigemptyset(&signal.sa_mask);
    signal.sa_flags = 0;
    ::sigaction(SIGFPE, &signal, NULL); // We don't use floating point. I hope so ;-)
    ::sigaction(SIGHUP, &signal, NULL);
    ::sigaction(SIGUSR1, &signal, NULL);
    ::sigaction(SIGTERM, &signal, NULL);
    ::sigaction(SIGALRM, &signal, NULL);

    setRecurringTimer(g_interval);

    cmdArgs.clear();

    // epoll
    epollAll(sourceIPNetwork, listenPort, targetPort, targetIPNetwork, sourceToTargeIPNetwork);

    if (g_shutdown)
        printInfo("Terminated by SIGTERM.");
}
