#ifndef PE_HEADER_PARSER_H
#define PE_HEADER_PARSER_H

typedef enum ParseHeaderRet {
    PE_OK,
    PE_ERROR,
    PE_UNKNOWN_FORMAT
} ParseHeaderRet;

ParseHeaderRet parse_header(void *params);

#endif /* PE_HEADER_PARSER_H */