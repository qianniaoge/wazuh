#include "hlpDetails.hpp"
#include "specificParsers.hpp"

const parserConfigFuncPtr kParsersConfig[] = {
    nullptr,
    configureAnyParser,
    nullptr,
    nullptr,
    configureTsParser,
    nullptr,
    nullptr,
    configureMapParser,
    configureDomainParser,
    configureFilepathParser,
    nullptr,
    configureKeywordParser,
    nullptr,
    configureQuotedString,
    nullptr,
};

const parserFuncPtr kAvailableParsers[] = {
    parseAny,
    parseAny,
    matchLiteral,
    parseIPaddress,
    parseTimeStamp,
    parseURL,
    parseJson,
    parseMap,
    parseDomain,
    parseFilePath,
    parseUserAgent,
    parseAny, //Keyword
    parseNumber,
    parseQuotedString,
    nullptr,
};
