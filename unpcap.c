#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#define BUF_SIZE 10000

#define PCAP_FILE_HEADER_LENGTH 24
#define PCAP_RECORD_HEADER_LENGTH 16
#define ETHERNET_HEADER_LENGTH 14
#define IP_HEADER_LENGTH 20
#define UDP_HEADER_LENGTH 8

typedef struct {
    unsigned int ts_sec : 32;
    unsigned int ts_usec : 32;
    unsigned int incl_len : 32;
    unsigned int orig_len : 32;
} PCAP_frame_header;

typedef struct {
    unsigned int magic : 32;
    unsigned int ver_major : 16;
    unsigned int ver_minor : 16;
    unsigned int t_zone : 32;
    unsigned int sig_figs : 32;
    unsigned int snap_len : 32;
    unsigned int network : 32;
} PCAP_file_header;

void set_binary_mode() {
    freopen(NULL, "rb", stdin);
    freopen(NULL, "wb", stdout);
}

void read_pcap_file_header() {
    PCAP_file_header pcap_file_header;
    size_t res = fread(&pcap_file_header, sizeof pcap_file_header, 1, stdin);
    if(res != 1) {
        perror("Failed to read PCAP record header");
        exit(-1);
    }
}

int get_pcap_frame_length() {
    PCAP_frame_header pcap_frame_header;
    size_t res = fread(&pcap_frame_header, sizeof pcap_frame_header, 1, stdin);
    if(res != 1) {
        perror("Failed to read PCAP record header");
        exit(-1);
    }
    return pcap_frame_header.incl_len;
}

void error_exit() {
    fflush(stdout);
    exit(-1);
}

void skip_pcap_file_header() {
    //read_pcap_file_header();
    int res = fseek(stdin, PCAP_FILE_HEADER_LENGTH, SEEK_SET);
    if(res != 0) {
        perror("Failed to skip PCAP file header %s\n");
        error_exit();
    }
}

int main(int argc, char *argv[]) {
    set_binary_mode();
    
    if (argc == 2 && strcmp(argv[1], "-s") == 0) {
        skip_pcap_file_header();
    }

    unsigned char buffer[BUF_SIZE] = {0};

    while(1) {
        if(feof(stdin)) {
            break;
        }
        int pcap_frame_len = get_pcap_frame_length();
        if(pcap_frame_len > BUF_SIZE) {
            fprintf(stderr, "The PCAP frame size %i is larger than allocated buffer size %i\n", pcap_frame_len, BUF_SIZE);
            error_exit();
        }
        fprintf(stderr, "%i\n", pcap_frame_len);

        size_t res = fread(buffer, pcap_frame_len, 1, stdin);
        if(res != 1) {
            perror("Unable to read full PCAP frame (incomplete frame?)\n");
            error_exit();
        }

        int vita_offset = ETHERNET_HEADER_LENGTH + IP_HEADER_LENGTH + UDP_HEADER_LENGTH;
        int vita_len = pcap_frame_len - vita_offset;

        res = fwrite(&buffer[vita_offset], vita_len, 1, stdout);
        if(res != 1) {
            perror("Failed to write VITA data\n");
            error_exit();
        }
    }
    
    fflush(stdout);
    fclose(stdout);
}

