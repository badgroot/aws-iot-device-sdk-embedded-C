#line 2 "suites/main_test.function"
/*
 * *** THIS FILE HAS BEEN MACHINE GENERATED ***
 *
 * This file has been machine generated using the script:
 * generate_test_code.py
 *
 * Test file      : ./test_suite_psa_crypto_slot_management.c
 *
 * The following files were used to create this file.
 *
 *      Main code file      : /home/ubuntu/work/git-repos/aws-iot-device-sdk-embedded-C/external_libs/mbedTLS/crypto/tests/suites/main_test.function
 *      Platform code file  : /home/ubuntu/work/git-repos/aws-iot-device-sdk-embedded-C/external_libs/mbedTLS/crypto/tests/suites/host_test.function
 *      Helper file         : /home/ubuntu/work/git-repos/aws-iot-device-sdk-embedded-C/external_libs/mbedTLS/crypto/tests/suites/helpers.function
 *      Test suite file     : /home/ubuntu/work/git-repos/aws-iot-device-sdk-embedded-C/external_libs/mbedTLS/crypto/tests/suites/test_suite_psa_crypto_slot_management.function
 *      Test suite data     : /home/ubuntu/work/git-repos/aws-iot-device-sdk-embedded-C/external_libs/mbedTLS/crypto/tests/suites/test_suite_psa_crypto_slot_management.data
 *
 *
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include <mbedtls/config.h>
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include "psa/crypto.h"
#endif /* MBEDTLS_USE_PSA_CRYPTO */

/*----------------------------------------------------------------------------*/
/* Common helper code */

#line 2 "suites/helpers.function"
/*----------------------------------------------------------------------------*/
/* Headers */

#include <stdlib.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_fprintf    fprintf
#define mbedtls_snprintf   snprintf
#define mbedtls_calloc     calloc
#define mbedtls_free       free
#define mbedtls_exit       exit
#define mbedtls_time       time
#define mbedtls_time_t     time_t
#define MBEDTLS_EXIT_SUCCESS EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE EXIT_FAILURE
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

#if defined(MBEDTLS_CHECK_PARAMS)
#include "mbedtls/platform_util.h"
#include <setjmp.h>
#endif

#ifdef _MSC_VER
#include <basetsd.h>
typedef UINT8 uint8_t;
typedef INT32 int32_t;
typedef UINT32 uint32_t;
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#else
#include <stdint.h>
#endif

#include <string.h>

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <unistd.h>
#include <strings.h>
#endif

/* Type for Hex parameters */
typedef struct data_tag
{
    uint8_t *   x;
    uint32_t    len;
} data_t;

/*----------------------------------------------------------------------------*/
/* Status and error constants */

#define DEPENDENCY_SUPPORTED            0   /* Dependency supported by build */
#define KEY_VALUE_MAPPING_FOUND         0   /* Integer expression found */
#define DISPATCH_TEST_SUCCESS           0   /* Test dispatch successful */

#define KEY_VALUE_MAPPING_NOT_FOUND     -1  /* Integer expression not found */
#define DEPENDENCY_NOT_SUPPORTED        -2  /* Dependency not supported */
#define DISPATCH_TEST_FN_NOT_FOUND      -3  /* Test function not found */
#define DISPATCH_INVALID_TEST_DATA      -4  /* Invalid test parameter type.
                                               Only int, string, binary data
                                               and integer expressions are
                                               allowed */
#define DISPATCH_UNSUPPORTED_SUITE      -5  /* Test suite not supported by the
                                               build */

typedef enum
{
    PARAMFAIL_TESTSTATE_IDLE = 0,           /* No parameter failure call test */
    PARAMFAIL_TESTSTATE_PENDING,            /* Test call to the parameter failure
                                             * is pending */
    PARAMFAIL_TESTSTATE_CALLED              /* The test call to the parameter
                                             * failure function has been made */
} paramfail_test_state_t;


/*----------------------------------------------------------------------------*/
/* Macros */

/**
 * \brief   This macro tests the expression passed to it as a test step or
 *          individual test in a test case.
 *
 *          It allows a library function to return a value and return an error
 *          code that can be tested.
 *
 *          When MBEDTLS_CHECK_PARAMS is enabled, calls to the parameter failure
 *          callback, MBEDTLS_PARAM_FAILED(), will be assumed to be a test
 *          failure.
 *
 *          This macro is not suitable for negative parameter validation tests,
 *          as it assumes the test step will not create an error.
 *
 *          Failing the test means:
 *          - Mark this test case as failed.
 *          - Print a message identifying the failure.
 *          - Jump to the \c exit label.
 *
 *          This macro expands to an instruction, not an expression.
 *          It may jump to the \c exit label.
 *
 * \param   TEST    The test expression to be tested.
 */
#define TEST_ASSERT( TEST )                                 \
    do {                                                    \
       if( ! (TEST) )                                       \
       {                                                    \
          test_fail( #TEST, __LINE__, __FILE__ );           \
          goto exit;                                        \
       }                                                    \
    } while( 0 )

/** Evaluate two expressions and fail the test case if they have different
 * values.
 *
 * \param expr1     An expression to evaluate.
 * \param expr2     The expected value of \p expr1. This can be any
 *                  expression, but it is typically a constant.
 */
#define TEST_EQUAL( expr1, expr2 )              \
    TEST_ASSERT( ( expr1 ) == ( expr2 ) )

/** Evaluate an expression and fail the test case if it returns an error.
 *
 * \param expr      The expression to evaluate. This is typically a call
 *                  to a \c psa_xxx function that returns a value of type
 *                  #psa_status_t.
 */
#define PSA_ASSERT( expr ) TEST_EQUAL( ( expr ), PSA_SUCCESS )

/** Allocate memory dynamically and fail the test case if this fails.
 *
 * You must set \p pointer to \c NULL before calling this macro and
 * put `mbedtls_free( pointer )` in the test's cleanup code.
 *
 * If \p length is zero, the resulting \p pointer will be \c NULL.
 * This is usually what we want in tests since API functions are
 * supposed to accept null pointers when a buffer size is zero.
 *
 * This macro expands to an instruction, not an expression.
 * It may jump to the \c exit label.
 *
 * \param pointer   An lvalue where the address of the allocated buffer
 *                  will be stored.
 *                  This expression may be evaluated multiple times.
 * \param length    Number of elements to allocate.
 *                  This expression may be evaluated multiple times.
 *
 */
#define ASSERT_ALLOC( pointer, length )                           \
    do                                                            \
    {                                                             \
        TEST_ASSERT( ( pointer ) == NULL );                       \
        if( ( length ) != 0 )                                     \
        {                                                         \
            ( pointer ) = mbedtls_calloc( sizeof( *( pointer ) ), \
                                          ( length ) );           \
            TEST_ASSERT( ( pointer ) != NULL );                   \
        }                                                         \
    }                                                             \
    while( 0 )

/** Compare two buffers and fail the test case if they differ.
 *
 * This macro expands to an instruction, not an expression.
 * It may jump to the \c exit label.
 *
 * \param p1        Pointer to the start of the first buffer.
 * \param size1     Size of the first buffer in bytes.
 *                  This expression may be evaluated multiple times.
 * \param p2        Pointer to the start of the second buffer.
 * \param size2     Size of the second buffer in bytes.
 *                  This expression may be evaluated multiple times.
 */
#define ASSERT_COMPARE( p1, size1, p2, size2 )                          \
    do                                                                  \
    {                                                                   \
        TEST_ASSERT( ( size1 ) == ( size2 ) );                          \
        if( ( size1 ) != 0 )                                            \
            TEST_ASSERT( memcmp( ( p1 ), ( p2 ), ( size1 ) ) == 0 );    \
    }                                                                   \
    while( 0 )

#if defined(MBEDTLS_CHECK_PARAMS) && !defined(MBEDTLS_PARAM_FAILED_ALT)
/**
 * \brief   This macro tests the statement passed to it as a test step or
 *          individual test in a test case. The macro assumes the test will fail
 *          and will generate an error.
 *
 *          It allows a library function to return a value and tests the return
 *          code on return to confirm the given error code was returned.
 *
 *          When MBEDTLS_CHECK_PARAMS is enabled, calls to the parameter failure
 *          callback, MBEDTLS_PARAM_FAILED(), are assumed to indicate the
 *          expected failure, and the test will pass.
 *
 *          This macro is intended for negative parameter validation tests,
 *          where the failing function may return an error value or call
 *          MBEDTLS_PARAM_FAILED() to indicate the error.
 *
 * \param   PARAM_ERROR_VALUE   The expected error code.
 *
 * \param   TEST                The test expression to be tested.
 */
#define TEST_INVALID_PARAM_RET( PARAM_ERR_VALUE, TEST )                     \
    do {                                                                    \
        test_info.paramfail_test_state = PARAMFAIL_TESTSTATE_PENDING;       \
        if( (TEST) != (PARAM_ERR_VALUE) ||                                  \
            test_info.paramfail_test_state != PARAMFAIL_TESTSTATE_CALLED )  \
        {                                                                   \
            test_fail( #TEST, __LINE__, __FILE__ );                         \
            goto exit;                                                      \
        }                                                                   \
   } while( 0 )

/**
 * \brief   This macro tests the statement passed to it as a test step or
 *          individual test in a test case. The macro assumes the test will fail
 *          and will generate an error.
 *
 *          It assumes the library function under test cannot return a value and
 *          assumes errors can only be indicated byt calls to
 *          MBEDTLS_PARAM_FAILED().
 *
 *          When MBEDTLS_CHECK_PARAMS is enabled, calls to the parameter failure
 *          callback, MBEDTLS_PARAM_FAILED(), are assumed to indicate the
 *          expected failure. If MBEDTLS_CHECK_PARAMS is not enabled, no test
 *          can be made.
 *
 *          This macro is intended for negative parameter validation tests,
 *          where the failing function can only return an error by calling
 *          MBEDTLS_PARAM_FAILED() to indicate the error.
 *
 * \param   TEST                The test expression to be tested.
 */
#define TEST_INVALID_PARAM( TEST )                                          \
    do {                                                                    \
        memcpy(jmp_tmp, param_fail_jmp, sizeof(jmp_buf));                   \
        if( setjmp( param_fail_jmp ) == 0 )                                 \
        {                                                                   \
            TEST;                                                           \
            test_fail( #TEST, __LINE__, __FILE__ );                         \
            goto exit;                                                      \
        }                                                                   \
        memcpy(param_fail_jmp, jmp_tmp, sizeof(jmp_buf));                   \
    } while( 0 )
#endif /* MBEDTLS_CHECK_PARAMS && !MBEDTLS_PARAM_FAILED_ALT */

/**
 * \brief   This macro tests the statement passed to it as a test step or
 *          individual test in a test case. The macro assumes the test will not fail.
 *
 *          It assumes the library function under test cannot return a value and
 *          assumes errors can only be indicated by calls to
 *          MBEDTLS_PARAM_FAILED().
 *
 *          When MBEDTLS_CHECK_PARAMS is enabled, calls to the parameter failure
 *          callback, MBEDTLS_PARAM_FAILED(), are assumed to indicate the
 *          expected failure. If MBEDTLS_CHECK_PARAMS is not enabled, no test
 *          can be made.
 *
 *          This macro is intended to test that functions returning void
 *          accept all of the parameter values they're supposed to accept - eg
 *          that they don't call MBEDTLS_PARAM_FAILED() when a parameter
 *          that's allowed to be NULL happens to be NULL.
 *
 *          Note: for functions that return something other that void,
 *          checking that they accept all the parameters they're supposed to
 *          accept is best done by using TEST_ASSERT() and checking the return
 *          value as well.
 *
 *          Note: this macro is available even when #MBEDTLS_CHECK_PARAMS is
 *          disabled, as it makes sense to check that the functions accept all
 *          legal values even if this option is disabled - only in that case,
 *          the test is more about whether the function segfaults than about
 *          whether it invokes MBEDTLS_PARAM_FAILED().
 *
 * \param   TEST                The test expression to be tested.
 */
#define TEST_VALID_PARAM( TEST )                                    \
    TEST_ASSERT( ( TEST, 1 ) );

#define TEST_HELPER_ASSERT(a) if( !( a ) )                                      \
{                                                                   \
    mbedtls_fprintf( stderr, "Assertion Failed at %s:%d - %s\n",   \
                             __FILE__, __LINE__, #a );              \
    mbedtls_exit( 1 );                                             \
}

#if defined(__GNUC__)
/* Test if arg and &(arg)[0] have the same type. This is true if arg is
 * an array but not if it's a pointer. */
#define IS_ARRAY_NOT_POINTER( arg )                                     \
    ( ! __builtin_types_compatible_p( __typeof__( arg ),                \
                                      __typeof__( &( arg )[0] ) ) )
#else
/* On platforms where we don't know how to implement this check,
 * omit it. Oh well, a non-portable check is better than nothing. */
#define IS_ARRAY_NOT_POINTER( arg ) 1
#endif

/* A compile-time constant with the value 0. If `const_expr` is not a
 * compile-time constant with a nonzero value, cause a compile-time error. */
#define STATIC_ASSERT_EXPR( const_expr )                                \
    ( 0 && sizeof( struct { int STATIC_ASSERT : 1 - 2 * ! ( const_expr ); } ) )
/* Return the scalar value `value` (possibly promoted). This is a compile-time
 * constant if `value` is. `condition` must be a compile-time constant.
 * If `condition` is false, arrange to cause a compile-time error. */
#define STATIC_ASSERT_THEN_RETURN( condition, value )   \
    ( STATIC_ASSERT_EXPR( condition ) ? 0 : ( value ) )

#define ARRAY_LENGTH_UNSAFE( array )            \
    ( sizeof( array ) / sizeof( *( array ) ) )
/** Return the number of elements of a static or stack array.
 *
 * \param array         A value of array (not pointer) type.
 *
 * \return The number of elements of the array.
 */
#define ARRAY_LENGTH( array )                                           \
    ( STATIC_ASSERT_THEN_RETURN( IS_ARRAY_NOT_POINTER( array ),         \
                                 ARRAY_LENGTH_UNSAFE( array ) ) )

/** Return the smaller of two values.
 *
 * \param x         An integer-valued expression without side effects.
 * \param y         An integer-valued expression without side effects.
 *
 * \return The smaller of \p x and \p y.
 */
#define MIN( x, y ) ( ( x ) < ( y ) ? ( x ) : ( y ) )

/** Return the larger of two values.
 *
 * \param x         An integer-valued expression without side effects.
 * \param y         An integer-valued expression without side effects.
 *
 * \return The larger of \p x and \p y.
 */
#define MAX( x, y ) ( ( x ) > ( y ) ? ( x ) : ( y ) )

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
        | ( (uint32_t) (b)[(i) + 1] << 16 )             \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 3]       );            \
}
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif


/*----------------------------------------------------------------------------*/
/* Global variables */

static struct
{
    paramfail_test_state_t paramfail_test_state;
    int failed;
    const char *test;
    const char *filename;
    int line_no;
}
test_info;

#if defined(MBEDTLS_PLATFORM_C)
mbedtls_platform_context platform_ctx;
#endif

#if defined(MBEDTLS_CHECK_PARAMS)
jmp_buf param_fail_jmp;
jmp_buf jmp_tmp;
#endif

/*----------------------------------------------------------------------------*/
/* Helper flags for complex dependencies */

/* Indicates whether we expect mbedtls_entropy_init
 * to initialize some strong entropy source. */
#if defined(MBEDTLS_TEST_NULL_ENTROPY) ||             \
    ( !defined(MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES) && \
      ( !defined(MBEDTLS_NO_PLATFORM_ENTROPY)  ||     \
         defined(MBEDTLS_HAVEGE_C)             ||     \
         defined(MBEDTLS_ENTROPY_HARDWARE_ALT) ||     \
         defined(ENTROPY_NV_SEED) ) )
#define ENTROPY_HAVE_STRONG
#endif


/*----------------------------------------------------------------------------*/
/* Helper Functions */

static void test_fail( const char *test, int line_no, const char* filename )
{
    test_info.failed = 1;
    test_info.test = test;
    test_info.line_no = line_no;
    test_info.filename = filename;
}

static int platform_setup()
{
    int ret = 0;
#if defined(MBEDTLS_PLATFORM_C)
    ret = mbedtls_platform_setup( &platform_ctx );
#endif /* MBEDTLS_PLATFORM_C */
    return( ret );
}

static void platform_teardown()
{
#if defined(MBEDTLS_PLATFORM_C)
    mbedtls_platform_teardown( &platform_ctx );
#endif /* MBEDTLS_PLATFORM_C */
}

#if defined(MBEDTLS_CHECK_PARAMS)
void mbedtls_param_failed( const char *failure_condition,
                           const char *file,
                           int line )
{
    /* If we are testing the callback function...  */
    if( test_info.paramfail_test_state == PARAMFAIL_TESTSTATE_PENDING )
    {
        test_info.paramfail_test_state = PARAMFAIL_TESTSTATE_CALLED;
    }
    else
    {
        /* ...else we treat this as an error */

        /* Record the location of the failure, but not as a failure yet, in case
         * it was part of the test */
        test_fail( failure_condition, line, file );
        test_info.failed = 0;

        longjmp( param_fail_jmp, 1 );
    }
}
#endif

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
static int redirect_output( FILE** out_stream, const char* path )
{
    int stdout_fd = dup( fileno( *out_stream ) );

    if( stdout_fd == -1 )
    {
        return -1;
    }

    fflush( *out_stream );
    fclose( *out_stream );
    *out_stream = fopen( path, "w" );

    if( *out_stream == NULL )
    {
        close( stdout_fd );
        return -1;
    }

    return stdout_fd;
}

static int restore_output( FILE** out_stream, int old_fd )
{
    fflush( *out_stream );
    fclose( *out_stream );

    *out_stream = fdopen( old_fd, "w" );
    if( *out_stream == NULL )
    {
        return -1;
    }

    return 0;
}

static void close_output( FILE* out_stream )
{
    fclose( out_stream );
}
#endif /* __unix__ || __APPLE__ __MACH__ */

static int unhexify( unsigned char *obuf, const char *ibuf )
{
    unsigned char c, c2;
    int len = strlen( ibuf ) / 2;
    TEST_HELPER_ASSERT( strlen( ibuf ) % 2 == 0 ); /* must be even number of bytes */

    while( *ibuf != 0 )
    {
        c = *ibuf++;
        if( c >= '0' && c <= '9' )
            c -= '0';
        else if( c >= 'a' && c <= 'f' )
            c -= 'a' - 10;
        else if( c >= 'A' && c <= 'F' )
            c -= 'A' - 10;
        else
            TEST_HELPER_ASSERT( 0 );

        c2 = *ibuf++;
        if( c2 >= '0' && c2 <= '9' )
            c2 -= '0';
        else if( c2 >= 'a' && c2 <= 'f' )
            c2 -= 'a' - 10;
        else if( c2 >= 'A' && c2 <= 'F' )
            c2 -= 'A' - 10;
        else
            TEST_HELPER_ASSERT( 0 );

        *obuf++ = ( c << 4 ) | c2;
    }

    return len;
}

static void hexify( unsigned char *obuf, const unsigned char *ibuf, int len )
{
    unsigned char l, h;

    while( len != 0 )
    {
        h = *ibuf / 16;
        l = *ibuf % 16;

        if( h < 10 )
            *obuf++ = '0' + h;
        else
            *obuf++ = 'a' + h - 10;

        if( l < 10 )
            *obuf++ = '0' + l;
        else
            *obuf++ = 'a' + l - 10;

        ++ibuf;
        len--;
    }
}

/**
 * Allocate and zeroize a buffer.
 *
 * If the size if zero, a pointer to a zeroized 1-byte buffer is returned.
 *
 * For convenience, dies if allocation fails.
 */
static unsigned char *zero_alloc( size_t len )
{
    void *p;
    size_t actual_len = ( len != 0 ) ? len : 1;

    p = mbedtls_calloc( 1, actual_len );
    TEST_HELPER_ASSERT( p != NULL );

    memset( p, 0x00, actual_len );

    return( p );
}

/**
 * Allocate and fill a buffer from hex data.
 *
 * The buffer is sized exactly as needed. This allows to detect buffer
 * overruns (including overreads) when running the test suite under valgrind.
 *
 * If the size if zero, a pointer to a zeroized 1-byte buffer is returned.
 *
 * For convenience, dies if allocation fails.
 */
static unsigned char *unhexify_alloc( const char *ibuf, size_t *olen )
{
    unsigned char *obuf;

    *olen = strlen( ibuf ) / 2;

    if( *olen == 0 )
        return( zero_alloc( *olen ) );

    obuf = mbedtls_calloc( 1, *olen );
    TEST_HELPER_ASSERT( obuf != NULL );

    (void) unhexify( obuf, ibuf );

    return( obuf );
}

/**
 * This function just returns data from rand().
 * Although predictable and often similar on multiple
 * runs, this does not result in identical random on
 * each run. So do not use this if the results of a
 * test depend on the random data that is generated.
 *
 * rng_state shall be NULL.
 */
static int rnd_std_rand( void *rng_state, unsigned char *output, size_t len )
{
#if !defined(__OpenBSD__)
    size_t i;

    if( rng_state != NULL )
        rng_state  = NULL;

    for( i = 0; i < len; ++i )
        output[i] = rand();
#else
    if( rng_state != NULL )
        rng_state = NULL;

    arc4random_buf( output, len );
#endif /* !OpenBSD */

    return( 0 );
}

/**
 * This function only returns zeros
 *
 * rng_state shall be NULL.
 */
static int rnd_zero_rand( void *rng_state, unsigned char *output, size_t len )
{
    if( rng_state != NULL )
        rng_state  = NULL;

    memset( output, 0, len );

    return( 0 );
}

typedef struct
{
    unsigned char *buf;
    size_t length;
} rnd_buf_info;

/**
 * This function returns random based on a buffer it receives.
 *
 * rng_state shall be a pointer to a rnd_buf_info structure.
 *
 * The number of bytes released from the buffer on each call to
 * the random function is specified by per_call. (Can be between
 * 1 and 4)
 *
 * After the buffer is empty it will return rand();
 */
static int rnd_buffer_rand( void *rng_state, unsigned char *output, size_t len )
{
    rnd_buf_info *info = (rnd_buf_info *) rng_state;
    size_t use_len;

    if( rng_state == NULL )
        return( rnd_std_rand( NULL, output, len ) );

    use_len = len;
    if( len > info->length )
        use_len = info->length;

    if( use_len )
    {
        memcpy( output, info->buf, use_len );
        info->buf += use_len;
        info->length -= use_len;
    }

    if( len - use_len > 0 )
        return( rnd_std_rand( NULL, output + use_len, len - use_len ) );

    return( 0 );
}

/**
 * Info structure for the pseudo random function
 *
 * Key should be set at the start to a test-unique value.
 * Do not forget endianness!
 * State( v0, v1 ) should be set to zero.
 */
typedef struct
{
    uint32_t key[16];
    uint32_t v0, v1;
} rnd_pseudo_info;

/**
 * This function returns random based on a pseudo random function.
 * This means the results should be identical on all systems.
 * Pseudo random is based on the XTEA encryption algorithm to
 * generate pseudorandom.
 *
 * rng_state shall be a pointer to a rnd_pseudo_info structure.
 */
static int rnd_pseudo_rand( void *rng_state, unsigned char *output, size_t len )
{
    rnd_pseudo_info *info = (rnd_pseudo_info *) rng_state;
    uint32_t i, *k, sum, delta=0x9E3779B9;
    unsigned char result[4], *out = output;

    if( rng_state == NULL )
        return( rnd_std_rand( NULL, output, len ) );

    k = info->key;

    while( len > 0 )
    {
        size_t use_len = ( len > 4 ) ? 4 : len;
        sum = 0;

        for( i = 0; i < 32; i++ )
        {
            info->v0 += ( ( ( info->v1 << 4 ) ^ ( info->v1 >> 5 ) )
                            + info->v1 ) ^ ( sum + k[sum & 3] );
            sum += delta;
            info->v1 += ( ( ( info->v0 << 4 ) ^ ( info->v0 >> 5 ) )
                            + info->v0 ) ^ ( sum + k[( sum>>11 ) & 3] );
        }

        PUT_UINT32_BE( info->v0, result, 0 );
        memcpy( out, result, use_len );
        len -= use_len;
        out += 4;
    }

    return( 0 );
}

int hexcmp( uint8_t * a, uint8_t * b, uint32_t a_len, uint32_t b_len )
{
    int ret = 0;
    uint32_t i = 0;

    if( a_len != b_len )
        return( -1 );

    for( i = 0; i < a_len; i++ )
    {
        if( a[i] != b[i] )
        {
            ret = -1;
            break;
        }
    }
    return ret;
}


#line 38 "suites/main_test.function"


/*----------------------------------------------------------------------------*/
/* Test Suite Code */


#define TEST_SUITE_ACTIVE

#if defined(MBEDTLS_PSA_CRYPTO_C)
#line 2 "/home/ubuntu/work/git-repos/aws-iot-device-sdk-embedded-C/external_libs/mbedTLS/crypto/tests/suites/test_suite_psa_crypto_slot_management.function"
#include <stdint.h>

#if defined(MBEDTLS_PSA_CRYPTO_SPM)
#include "spm/psa_defs.h"
#endif
#include "psa/crypto.h"

#include "psa_crypto_storage.h"

typedef enum
{
    CLOSE_BY_CLOSE,
    CLOSE_BY_DESTROY,
    CLOSE_BY_SHUTDOWN,
} close_method_t;

typedef enum
{
    KEEP_OPEN,
    CLOSE_BEFORE,
    CLOSE_AFTER,
} reopen_policy_t;

/* All test functions that create persistent keys must call
 * `TEST_MAX_KEY_ID( key_id )` before creating a persistent key with this
 * identifier, and must call psa_purge_key_storage() in their cleanup
 * code. */

#if defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
/* There is no API to purge all keys. For this test suite, require that
 * all key IDs be less than a certain maximum, or a well-known value
 * which corresponds to a file that does not contain a key. */
#define MAX_KEY_ID_FOR_TEST 32
#define KEY_ID_IS_WELL_KNOWN( key_id )                  \
    ( ( key_id ) == PSA_CRYPTO_ITS_RANDOM_SEED_UID )
#define TEST_MAX_KEY_ID( key_id )                       \
    TEST_ASSERT( ( key_id ) <= MAX_KEY_ID_FOR_TEST ||   \
                 KEY_ID_IS_WELL_KNOWN( key_id ) )
void psa_purge_key_storage( void )
{
    psa_key_id_t i;
    /* The tests may have potentially created key ids from 1 to
     * MAX_KEY_ID_FOR_TEST. In addition, run the destroy function on key id
     * 0, which file-based storage uses as a temporary file. */
    for( i = 0; i <= MAX_KEY_ID_FOR_TEST; i++ )
        psa_destroy_persistent_key( i );
}
#else
#define TEST_MAX_KEY_ID( key_id ) ( (void) ( key_id ) )
#endif /* MBEDTLS_PSA_CRYPTO_STORAGE_C */

static int psa_key_policy_equal( psa_key_policy_t *p1,
                                 psa_key_policy_t *p2 )
{
    return( psa_key_policy_get_usage( p1 ) == psa_key_policy_get_usage( p2 ) &&
            psa_key_policy_get_algorithm( p1 ) == psa_key_policy_get_algorithm( p2 ) );
}

#line 68 "/home/ubuntu/work/git-repos/aws-iot-device-sdk-embedded-C/external_libs/mbedTLS/crypto/tests/suites/test_suite_psa_crypto_slot_management.function"
void test_transient_slot_lifecycle( int usage_arg, int alg_arg,
                               int type_arg, data_t *key_data,
                               int close_method_arg )
{
    psa_algorithm_t alg = alg_arg;
    psa_key_usage_t usage_flags = usage_arg;
    psa_key_type_t type = type_arg;
    close_method_t close_method = close_method_arg;
    psa_key_type_t read_type;
    psa_key_handle_t handle = 0;
    psa_key_policy_t policy = PSA_KEY_POLICY_INIT;

    PSA_ASSERT( psa_crypto_init( ) );

    /* Get a handle and import a key. */
    PSA_ASSERT( psa_allocate_key( &handle ) );
    TEST_ASSERT( handle != 0 );
    psa_key_policy_set_usage( &policy, usage_flags, alg );
    PSA_ASSERT( psa_set_key_policy( handle, &policy ) );
    PSA_ASSERT( psa_import_key( handle, type, key_data->x, key_data->len ) );
    PSA_ASSERT( psa_get_key_information( handle, &read_type, NULL ) );
    TEST_EQUAL( read_type, type );

    /* Do something that invalidates the handle. */
    switch( close_method )
    {
        case CLOSE_BY_CLOSE:
            PSA_ASSERT( psa_close_key( handle ) );
            break;
        case CLOSE_BY_DESTROY:
            PSA_ASSERT( psa_destroy_key( handle ) );
            break;
        case CLOSE_BY_SHUTDOWN:
            mbedtls_psa_crypto_free( );
            PSA_ASSERT( psa_crypto_init( ) );
            break;
    }
    /* Test that the handle is now invalid. */
    TEST_EQUAL( psa_get_key_information( handle, &read_type, NULL ),
                PSA_ERROR_INVALID_HANDLE );
    TEST_EQUAL( psa_close_key( handle ), PSA_ERROR_INVALID_HANDLE );

exit:
    mbedtls_psa_crypto_free( );
}

void test_transient_slot_lifecycle_wrapper( void ** params )
{
    data_t data3 = {(uint8_t *) params[3], *( (uint32_t *) params[4] )};

    test_transient_slot_lifecycle( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), &data3, *( (int *) params[5] ) );
}
#if defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
#line 116 "/home/ubuntu/work/git-repos/aws-iot-device-sdk-embedded-C/external_libs/mbedTLS/crypto/tests/suites/test_suite_psa_crypto_slot_management.function"
void test_persistent_slot_lifecycle( int lifetime_arg, int id_arg,
                                int usage_arg, int alg_arg, int alg2_arg,
                                int type_arg, data_t *key_data,
                                int close_method_arg )
{
    psa_key_lifetime_t lifetime = lifetime_arg;
    psa_key_id_t id = id_arg;
    psa_algorithm_t alg = alg_arg;
    psa_algorithm_t alg2 = alg2_arg;
    psa_key_usage_t usage_flags = usage_arg;
    psa_key_type_t type = type_arg;
    size_t bits;
    close_method_t close_method = close_method_arg;
    psa_key_type_t read_type;
    size_t read_bits;
    psa_key_handle_t handle = 0;
    psa_key_policy_t policy = PSA_KEY_POLICY_INIT;
    psa_key_policy_t read_policy = PSA_KEY_POLICY_INIT;
    uint8_t *reexported = NULL;
    size_t reexported_length = -1;

    TEST_MAX_KEY_ID( id );

    PSA_ASSERT( psa_crypto_init( ) );

    /* Get a handle and import a key. */
    PSA_ASSERT( psa_create_key( lifetime, id, &handle ) );
    TEST_ASSERT( handle != 0 );
    psa_key_policy_set_usage( &policy, usage_flags, alg );
    psa_key_policy_set_enrollment_algorithm( &policy, alg2 );
    PSA_ASSERT( psa_set_key_policy( handle, &policy ) );
    PSA_ASSERT( psa_import_key( handle, type, key_data->x, key_data->len ) );
    PSA_ASSERT( psa_get_key_information( handle, &read_type, &bits ) );
    TEST_EQUAL( read_type, type );

    /* Close the key and reopen it. */
    PSA_ASSERT( psa_close_key( handle ) );
    PSA_ASSERT( psa_open_key( lifetime, id, &handle ) );
    PSA_ASSERT( psa_get_key_information( handle, &read_type, NULL ) );
    TEST_EQUAL( read_type, type );

    /* Do something that invalidates the handle. */
    switch( close_method )
    {
        case CLOSE_BY_CLOSE:
            PSA_ASSERT( psa_close_key( handle ) );
            break;
        case CLOSE_BY_DESTROY:
            PSA_ASSERT( psa_destroy_key( handle ) );
            break;
        case CLOSE_BY_SHUTDOWN:
            mbedtls_psa_crypto_free( );
            PSA_ASSERT( psa_crypto_init( ) );
            break;
    }
    /* Test that the handle is now invalid. */
    TEST_EQUAL( psa_get_key_information( handle, &read_type, NULL ),
                PSA_ERROR_INVALID_HANDLE );
    TEST_EQUAL( psa_close_key( handle ), PSA_ERROR_INVALID_HANDLE );

    /* Try to reopen the key. If we destroyed it, check that it doesn't
     * exist. Otherwise check that it still exists and has the expected
     * content. */
    switch( close_method )
    {
        case CLOSE_BY_CLOSE:
        case CLOSE_BY_SHUTDOWN:
            PSA_ASSERT( psa_open_key( lifetime, id, &handle ) );
            PSA_ASSERT( psa_get_key_policy( handle, &read_policy ) );
            PSA_ASSERT( psa_get_key_information( handle,
                                                 &read_type, &read_bits ) );
            TEST_EQUAL( read_type, type );
            TEST_EQUAL( read_bits, bits );
            TEST_EQUAL( psa_key_policy_get_usage( &read_policy ), usage_flags );
            TEST_EQUAL( psa_key_policy_get_algorithm( &read_policy ), alg );
            TEST_EQUAL( psa_key_policy_get_enrollment_algorithm( &read_policy ),
                        alg2 );
            if( policy.usage & PSA_KEY_USAGE_EXPORT )
            {
                ASSERT_ALLOC( reexported, key_data->len );
                PSA_ASSERT( psa_export_key( handle,
                                            reexported, key_data->len,
                                            &reexported_length ) );
                ASSERT_COMPARE( key_data->x, key_data->len,
                                reexported, reexported_length );
            }
            else
            {
                TEST_EQUAL( psa_export_key( handle,
                                            reexported, sizeof( reexported ),
                                            &reexported_length ),
                            PSA_ERROR_NOT_PERMITTED );
            }
            break;
        case CLOSE_BY_DESTROY:
            TEST_EQUAL( psa_open_key( lifetime, id, &handle ),
                        PSA_ERROR_DOES_NOT_EXIST );
            break;
    }

exit:
    mbedtls_psa_crypto_free( );
    psa_purge_key_storage( );
    mbedtls_free( reexported );
}

void test_persistent_slot_lifecycle_wrapper( void ** params )
{
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};

    test_persistent_slot_lifecycle( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), *( (int *) params[3] ), *( (int *) params[4] ), *( (int *) params[5] ), &data6, *( (int *) params[8] ) );
}
#endif /* MBEDTLS_PSA_CRYPTO_STORAGE_C */
#if defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
#line 224 "/home/ubuntu/work/git-repos/aws-iot-device-sdk-embedded-C/external_libs/mbedTLS/crypto/tests/suites/test_suite_psa_crypto_slot_management.function"
void test_create_existent( int lifetime_arg, int id_arg,
                      int reopen_policy_arg )
{
    psa_key_lifetime_t lifetime = lifetime_arg;
    psa_key_id_t id = id_arg;
    psa_key_handle_t handle1 = 0, handle2 = 0;
    psa_key_policy_t policy1 = PSA_KEY_POLICY_INIT;
    psa_key_policy_t read_policy = PSA_KEY_POLICY_INIT;
    psa_key_type_t type1 = PSA_KEY_TYPE_RAW_DATA;
    psa_key_type_t read_type;
    const uint8_t material1[16] = "test material #1";
    size_t bits1 = PSA_BYTES_TO_BITS( sizeof( material1 ) );
    size_t read_bits;
    uint8_t reexported[sizeof( material1 )];
    size_t reexported_length;
    reopen_policy_t reopen_policy = reopen_policy_arg;

    TEST_MAX_KEY_ID( id );

    PSA_ASSERT( psa_crypto_init( ) );

    /* Create a key. */
    PSA_ASSERT( psa_create_key( lifetime, id, &handle1 ) );
    TEST_ASSERT( handle1 != 0 );
    psa_key_policy_set_usage( &policy1, PSA_KEY_USAGE_EXPORT, 0 );
    PSA_ASSERT( psa_set_key_policy( handle1, &policy1 ) );
    PSA_ASSERT( psa_import_key( handle1, type1,
                                material1, sizeof( material1 ) ) );

    if( reopen_policy == CLOSE_BEFORE )
        PSA_ASSERT( psa_close_key( handle1 ) );

    /* Attempt to create a new key in the same slot. */
    TEST_EQUAL( psa_create_key( lifetime, id, &handle2 ),
                PSA_ERROR_ALREADY_EXISTS );
    TEST_EQUAL( handle2, 0 );

    if( reopen_policy == CLOSE_AFTER )
        PSA_ASSERT( psa_close_key( handle1 ) );
    if( reopen_policy == CLOSE_BEFORE || reopen_policy == CLOSE_AFTER )
        PSA_ASSERT( psa_open_key( lifetime, id, &handle1 ) );

    /* Check that the original key hasn't changed. */
    PSA_ASSERT( psa_get_key_policy( handle1, &read_policy ) );
    TEST_ASSERT( psa_key_policy_equal( &read_policy, &policy1 ) );
    PSA_ASSERT( psa_get_key_information( handle1, &read_type, &read_bits ) );
    TEST_EQUAL( read_type, type1 );
    TEST_EQUAL( read_bits, bits1 );
    PSA_ASSERT( psa_export_key( handle1,
                                reexported, sizeof( reexported ),
                                &reexported_length ) );
    ASSERT_COMPARE( material1, sizeof( material1 ),
                    reexported, reexported_length );

exit:
    mbedtls_psa_crypto_free( );
    psa_purge_key_storage( );
}

void test_create_existent_wrapper( void ** params )
{

    test_create_existent( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ) );
}
#endif /* MBEDTLS_PSA_CRYPTO_STORAGE_C */
#line 285 "/home/ubuntu/work/git-repos/aws-iot-device-sdk-embedded-C/external_libs/mbedTLS/crypto/tests/suites/test_suite_psa_crypto_slot_management.function"
void test_open_fail( int lifetime_arg, int id_arg,
                int expected_status_arg )
{
    psa_key_lifetime_t lifetime = lifetime_arg;
    psa_key_id_t id = id_arg;
    psa_status_t expected_status = expected_status_arg;
    psa_key_handle_t handle = 0xdead;

    PSA_ASSERT( psa_crypto_init( ) );

    TEST_EQUAL( psa_open_key( lifetime, id, &handle ), expected_status );
    TEST_EQUAL( handle, 0 );

exit:
    mbedtls_psa_crypto_free( );
}

void test_open_fail_wrapper( void ** params )
{

    test_open_fail( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ) );
}
#line 304 "/home/ubuntu/work/git-repos/aws-iot-device-sdk-embedded-C/external_libs/mbedTLS/crypto/tests/suites/test_suite_psa_crypto_slot_management.function"
void test_create_fail( int lifetime_arg, int id_arg,
                  int expected_status_arg )
{
    psa_key_lifetime_t lifetime = lifetime_arg;
    psa_key_id_t id = id_arg;
    psa_status_t expected_status = expected_status_arg;
    psa_key_handle_t handle = 0xdead;

    TEST_MAX_KEY_ID( id );

    PSA_ASSERT( psa_crypto_init( ) );

    TEST_EQUAL( psa_create_key( lifetime, id, &handle ),
                expected_status );
    TEST_EQUAL( handle, 0 );

exit:
    mbedtls_psa_crypto_free( );
#if defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
    psa_purge_key_storage( );
#endif
}

void test_create_fail_wrapper( void ** params )
{

    test_create_fail( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ) );
}
#line 329 "/home/ubuntu/work/git-repos/aws-iot-device-sdk-embedded-C/external_libs/mbedTLS/crypto/tests/suites/test_suite_psa_crypto_slot_management.function"
void test_copy_across_lifetimes( int source_lifetime_arg, int source_id_arg,
                            int source_usage_arg,
                            int source_alg_arg, int source_alg2_arg,
                            int type_arg, data_t *material,
                            int target_lifetime_arg, int target_id_arg,
                            int target_usage_arg,
                            int target_alg_arg, int target_alg2_arg,
                            int expected_usage_arg,
                            int expected_alg_arg, int expected_alg2_arg )
{
    psa_key_lifetime_t source_lifetime = source_lifetime_arg;
    psa_key_id_t source_id = source_id_arg;
    psa_key_usage_t source_usage = source_usage_arg;
    psa_algorithm_t source_alg = source_alg_arg;
    psa_algorithm_t source_alg2 = source_alg2_arg;
    psa_key_handle_t source_handle = 0;
    psa_key_policy_t source_policy = PSA_KEY_POLICY_INIT;
    psa_key_type_t source_type = type_arg;
    size_t source_bits;
    psa_key_lifetime_t target_lifetime = target_lifetime_arg;
    psa_key_id_t target_id = target_id_arg;
    psa_key_usage_t target_usage = target_usage_arg;
    psa_algorithm_t target_alg = target_alg_arg;
    psa_algorithm_t target_alg2 = target_alg2_arg;
    psa_key_handle_t target_handle = 0;
    psa_key_policy_t target_policy = PSA_KEY_POLICY_INIT;
    psa_key_type_t target_type;
    size_t target_bits;
    psa_key_usage_t expected_usage = expected_usage_arg;
    psa_algorithm_t expected_alg = expected_alg_arg;
    psa_algorithm_t expected_alg2 = expected_alg2_arg;
    uint8_t *export_buffer = NULL;

    TEST_MAX_KEY_ID( source_id );
    TEST_MAX_KEY_ID( target_id );

    PSA_ASSERT( psa_crypto_init( ) );

    /* Populate the source slot. */
    if( source_lifetime == PSA_KEY_LIFETIME_VOLATILE )
        PSA_ASSERT( psa_allocate_key( &source_handle ) );
    else
        PSA_ASSERT( psa_create_key( source_lifetime, source_id,
                                    &source_handle ) );
    psa_key_policy_set_usage( &source_policy, source_usage, source_alg );
    psa_key_policy_set_enrollment_algorithm( &source_policy, source_alg2 );
    PSA_ASSERT( psa_set_key_policy( source_handle, &source_policy ) );
    PSA_ASSERT( psa_import_key( source_handle, source_type,
                                material->x, material->len ) );
    PSA_ASSERT( psa_get_key_information( source_handle, NULL, &source_bits ) );

    /* Prepare the target slot. */
    if( target_lifetime == PSA_KEY_LIFETIME_VOLATILE )
        PSA_ASSERT( psa_allocate_key( &target_handle ) );
    else
        PSA_ASSERT( psa_create_key( target_lifetime, target_id,
                                    &target_handle ) );
    psa_key_policy_set_usage( &target_policy, target_usage, target_alg );
    psa_key_policy_set_enrollment_algorithm( &target_policy, target_alg2 );
    PSA_ASSERT( psa_set_key_policy( target_handle, &target_policy ) );
    target_policy = psa_key_policy_init();

    /* Copy the key. */
    PSA_ASSERT( psa_copy_key( source_handle, target_handle, NULL ) );

    /* Destroy the source to ensure that this doesn't affect the target. */
    PSA_ASSERT( psa_destroy_key( source_handle ) );

    /* If the target key is persistent, restart the system to make
     * sure that the material is still alive. */
    if( target_lifetime != PSA_KEY_LIFETIME_VOLATILE )
    {
        mbedtls_psa_crypto_free( );
        PSA_ASSERT( psa_crypto_init( ) );
        PSA_ASSERT( psa_open_key( target_lifetime, target_id,
                                  &target_handle ) );
    }

    /* Test that the target slot has the expected content. */
    PSA_ASSERT( psa_get_key_information( target_handle,
                                         &target_type, &target_bits ) );
    TEST_EQUAL( source_type, target_type );
    TEST_EQUAL( source_bits, target_bits );
    PSA_ASSERT( psa_get_key_policy( target_handle, &target_policy ) );
    TEST_EQUAL( expected_usage, psa_key_policy_get_usage( &target_policy ) );
    TEST_EQUAL( expected_alg, psa_key_policy_get_algorithm( &target_policy ) );
    TEST_EQUAL( expected_alg2,
                psa_key_policy_get_enrollment_algorithm( &target_policy ) );
    if( expected_usage & PSA_KEY_USAGE_EXPORT )
    {
        size_t length;
        ASSERT_ALLOC( export_buffer, material->len );
        PSA_ASSERT( psa_export_key( target_handle, export_buffer,
                                    material->len, &length ) );
        ASSERT_COMPARE( material->x, material->len,
                        export_buffer, length );
    }

exit:
    mbedtls_psa_crypto_free( );
    mbedtls_free( export_buffer );
#if defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
    psa_purge_key_storage( );
#endif
}

void test_copy_across_lifetimes_wrapper( void ** params )
{
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};

    test_copy_across_lifetimes( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), *( (int *) params[3] ), *( (int *) params[4] ), *( (int *) params[5] ), &data6, *( (int *) params[8] ), *( (int *) params[9] ), *( (int *) params[10] ), *( (int *) params[11] ), *( (int *) params[12] ), *( (int *) params[13] ), *( (int *) params[14] ), *( (int *) params[15] ) );
}
#line 437 "/home/ubuntu/work/git-repos/aws-iot-device-sdk-embedded-C/external_libs/mbedTLS/crypto/tests/suites/test_suite_psa_crypto_slot_management.function"
void test_copy_from_empty( int source_lifetime_arg, int source_id_arg,
                       int source_usage_arg, int source_alg_arg,
                       int target_lifetime_arg, int target_id_arg,
                       int target_usage_arg, int target_alg_arg )
{
    psa_key_lifetime_t source_lifetime = source_lifetime_arg;
    psa_key_id_t source_id = source_id_arg;
    psa_key_usage_t source_usage = source_usage_arg;
    psa_algorithm_t source_alg = source_alg_arg;
    psa_key_handle_t source_handle = 0;
    psa_key_policy_t source_policy = PSA_KEY_POLICY_INIT;
    psa_key_lifetime_t target_lifetime = target_lifetime_arg;
    psa_key_id_t target_id = target_id_arg;
    psa_key_usage_t target_usage = target_usage_arg;
    psa_algorithm_t target_alg = target_alg_arg;
    psa_key_handle_t target_handle = 0;
    psa_key_policy_t target_policy = PSA_KEY_POLICY_INIT;
    psa_key_policy_t got_policy;

    TEST_MAX_KEY_ID( source_id );
    TEST_MAX_KEY_ID( target_id );

    PSA_ASSERT( psa_crypto_init( ) );

    /* Prepare the source slot. */
    if( source_lifetime == PSA_KEY_LIFETIME_VOLATILE )
        PSA_ASSERT( psa_allocate_key( &source_handle ) );
    else
        PSA_ASSERT( psa_create_key( source_lifetime, source_id,
                                    &source_handle ) );
    psa_key_policy_set_usage( &source_policy, source_usage, source_alg );
    PSA_ASSERT( psa_set_key_policy( source_handle, &source_policy ) );

    /* Prepare the target slot. */
    if( target_lifetime == PSA_KEY_LIFETIME_VOLATILE )
        PSA_ASSERT( psa_allocate_key( &target_handle ) );
    else
        PSA_ASSERT( psa_create_key( target_lifetime, target_id,
                                    &target_handle ) );
    psa_key_policy_set_usage( &target_policy, target_usage, target_alg );
    PSA_ASSERT( psa_set_key_policy( target_handle, &target_policy ) );

    /* Copy the key. */
    TEST_EQUAL( psa_copy_key( source_handle, target_handle, NULL ),
                PSA_ERROR_DOES_NOT_EXIST );

    /* Test that the slots are unaffected. */
    PSA_ASSERT( psa_get_key_policy( source_handle, &got_policy ) );
    TEST_EQUAL( source_usage, psa_key_policy_get_usage( &got_policy ) );
    TEST_EQUAL( source_alg, psa_key_policy_get_algorithm( &got_policy ) );
    PSA_ASSERT( psa_get_key_policy( target_handle, &got_policy ) );
    TEST_EQUAL( target_usage, psa_key_policy_get_usage( &got_policy ) );
    TEST_EQUAL( target_alg, psa_key_policy_get_algorithm( &got_policy ) );

exit:
    mbedtls_psa_crypto_free( );
#if defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
    psa_purge_key_storage( );
#endif
}

void test_copy_from_empty_wrapper( void ** params )
{

    test_copy_from_empty( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), *( (int *) params[3] ), *( (int *) params[4] ), *( (int *) params[5] ), *( (int *) params[6] ), *( (int *) params[7] ) );
}
#line 500 "/home/ubuntu/work/git-repos/aws-iot-device-sdk-embedded-C/external_libs/mbedTLS/crypto/tests/suites/test_suite_psa_crypto_slot_management.function"
void test_copy_to_occupied( int source_lifetime_arg, int source_id_arg,
                       int source_usage_arg, int source_alg_arg,
                       int source_type_arg, data_t *source_material,
                       int target_lifetime_arg, int target_id_arg,
                       int target_usage_arg, int target_alg_arg,
                       int target_type_arg, data_t *target_material )
{
    psa_key_lifetime_t source_lifetime = source_lifetime_arg;
    psa_key_id_t source_id = source_id_arg;
    psa_key_usage_t source_usage = source_usage_arg;
    psa_algorithm_t source_alg = source_alg_arg;
    psa_key_handle_t source_handle = 0;
    psa_key_policy_t source_policy = PSA_KEY_POLICY_INIT;
    psa_key_type_t source_type = source_type_arg;
    size_t source_bits;
    psa_key_lifetime_t target_lifetime = target_lifetime_arg;
    psa_key_id_t target_id = target_id_arg;
    psa_key_usage_t target_usage = target_usage_arg;
    psa_algorithm_t target_alg = target_alg_arg;
    psa_key_handle_t target_handle = 0;
    psa_key_policy_t target_policy = PSA_KEY_POLICY_INIT;
    psa_key_type_t target_type = target_type_arg;
    size_t target_bits;
    psa_key_policy_t got_policy;
    psa_key_type_t got_type;
    size_t got_bits;
    uint8_t *export_buffer = NULL;

    TEST_MAX_KEY_ID( source_id );
    TEST_MAX_KEY_ID( target_id );

    PSA_ASSERT( psa_crypto_init( ) );

    /* Populate the source slot. */
    if( source_lifetime == PSA_KEY_LIFETIME_VOLATILE )
        PSA_ASSERT( psa_allocate_key( &source_handle ) );
    else
        PSA_ASSERT( psa_create_key( source_lifetime, source_id,
                                    &source_handle ) );
    psa_key_policy_set_usage( &source_policy, source_usage, source_alg );
    PSA_ASSERT( psa_set_key_policy( source_handle, &source_policy ) );
    PSA_ASSERT( psa_import_key( source_handle, source_type,
                                source_material->x, source_material->len ) );
    PSA_ASSERT( psa_get_key_information( source_handle, NULL, &source_bits ) );

    /* Populate the target slot. */
    if( target_lifetime == PSA_KEY_LIFETIME_VOLATILE )
        PSA_ASSERT( psa_allocate_key( &target_handle ) );
    else
        PSA_ASSERT( psa_create_key( target_lifetime, target_id,
                                    &target_handle ) );
    psa_key_policy_set_usage( &target_policy, target_usage, target_alg );
    PSA_ASSERT( psa_set_key_policy( target_handle, &target_policy ) );
    PSA_ASSERT( psa_import_key( target_handle, target_type,
                                target_material->x, target_material->len ) );
    PSA_ASSERT( psa_get_key_information( target_handle, NULL, &target_bits ) );

    /* Copy the key. */
    TEST_EQUAL( psa_copy_key( source_handle, target_handle, NULL ),
                PSA_ERROR_ALREADY_EXISTS );

    /* Test that the target slot is unaffected. */
    PSA_ASSERT( psa_get_key_information( target_handle,
                                         &got_type, &got_bits ) );
    TEST_EQUAL( target_type, got_type );
    TEST_EQUAL( target_bits, got_bits );
    PSA_ASSERT( psa_get_key_policy( target_handle, &got_policy ) );
    TEST_EQUAL( target_usage, psa_key_policy_get_usage( &got_policy ) );
    TEST_EQUAL( target_alg, psa_key_policy_get_algorithm( &got_policy ) );
    if( target_usage & PSA_KEY_USAGE_EXPORT )
    {
        size_t length;
        ASSERT_ALLOC( export_buffer, target_material->len );
        PSA_ASSERT( psa_export_key( target_handle, export_buffer,
                                    target_material->len, &length ) );
        ASSERT_COMPARE( target_material->x, target_material->len,
                        export_buffer, length );
    }

exit:
    mbedtls_psa_crypto_free( );
    mbedtls_free( export_buffer );
#if defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
    psa_purge_key_storage( );
#endif
}

void test_copy_to_occupied_wrapper( void ** params )
{
    data_t data5 = {(uint8_t *) params[5], *( (uint32_t *) params[6] )};
    data_t data12 = {(uint8_t *) params[12], *( (uint32_t *) params[13] )};

    test_copy_to_occupied( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), *( (int *) params[3] ), *( (int *) params[4] ), &data5, *( (int *) params[7] ), *( (int *) params[8] ), *( (int *) params[9] ), *( (int *) params[10] ), *( (int *) params[11] ), &data12 );
}
#line 589 "/home/ubuntu/work/git-repos/aws-iot-device-sdk-embedded-C/external_libs/mbedTLS/crypto/tests/suites/test_suite_psa_crypto_slot_management.function"
void test_copy_to_same( int lifetime_arg, int id_arg,
                   int usage_arg, int alg_arg,
                   int type_arg, data_t *material )
{
    psa_key_lifetime_t lifetime = lifetime_arg;
    psa_key_id_t id = id_arg;
    psa_key_usage_t usage = usage_arg;
    psa_algorithm_t alg = alg_arg;
    psa_key_handle_t handle = 0;
    psa_key_policy_t policy = PSA_KEY_POLICY_INIT;
    psa_key_type_t type = type_arg;
    size_t bits;
    psa_key_policy_t got_policy;
    psa_key_type_t got_type;
    size_t got_bits;
    uint8_t *export_buffer = NULL;

    TEST_MAX_KEY_ID( id );

    PSA_ASSERT( psa_crypto_init( ) );

    /* Populate the slot. */
    if( lifetime == PSA_KEY_LIFETIME_VOLATILE )
        PSA_ASSERT( psa_allocate_key( &handle ) );
    else
        PSA_ASSERT( psa_create_key( lifetime, id,
                                    &handle ) );
    psa_key_policy_set_usage( &policy, usage, alg );
    PSA_ASSERT( psa_set_key_policy( handle, &policy ) );
    PSA_ASSERT( psa_import_key( handle, type,
                                material->x, material->len ) );
    PSA_ASSERT( psa_get_key_information( handle, NULL, &bits ) );

    /* Copy the key. */
    TEST_EQUAL( psa_copy_key( handle, handle, NULL ),
                PSA_ERROR_ALREADY_EXISTS );

    /* Test that the slot is unaffected. */
    PSA_ASSERT( psa_get_key_information( handle,
                                         &got_type, &got_bits ) );
    TEST_EQUAL( type, got_type );
    TEST_EQUAL( bits, got_bits );
    PSA_ASSERT( psa_get_key_policy( handle, &got_policy ) );
    TEST_EQUAL( usage, psa_key_policy_get_usage( &got_policy ) );
    TEST_EQUAL( alg, psa_key_policy_get_algorithm( &got_policy ) );
    if( usage & PSA_KEY_USAGE_EXPORT )
    {
        size_t length;
        ASSERT_ALLOC( export_buffer, material->len );
        PSA_ASSERT( psa_export_key( handle, export_buffer,
                                    material->len, &length ) );
        ASSERT_COMPARE( material->x, material->len,
                        export_buffer, length );
    }

exit:
    mbedtls_psa_crypto_free( );
    mbedtls_free( export_buffer );
#if defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
    psa_purge_key_storage( );
#endif
}

void test_copy_to_same_wrapper( void ** params )
{
    data_t data5 = {(uint8_t *) params[5], *( (uint32_t *) params[6] )};

    test_copy_to_same( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), *( (int *) params[3] ), *( (int *) params[4] ), &data5 );
}
#line 654 "/home/ubuntu/work/git-repos/aws-iot-device-sdk-embedded-C/external_libs/mbedTLS/crypto/tests/suites/test_suite_psa_crypto_slot_management.function"
void test_invalid_handle( )
{
    psa_key_handle_t handle1 = 0;
    psa_key_policy_t policy = PSA_KEY_POLICY_INIT;
    psa_key_type_t read_type;
    size_t read_bits;
    uint8_t material[1] = "a";

    PSA_ASSERT( psa_crypto_init( ) );

    /* Allocate a handle and store a key in it. */
    PSA_ASSERT( psa_allocate_key( &handle1 ) );
    TEST_ASSERT( handle1 != 0 );
    psa_key_policy_set_usage( &policy, 0, 0 );
    PSA_ASSERT( psa_set_key_policy( handle1, &policy ) );
    PSA_ASSERT( psa_import_key( handle1, PSA_KEY_TYPE_RAW_DATA,
                                material, sizeof( material ) ) );

    /* Attempt to close and destroy some invalid handles. */
    TEST_EQUAL( psa_close_key( 0 ), PSA_ERROR_INVALID_HANDLE );
    TEST_EQUAL( psa_close_key( handle1 - 1 ), PSA_ERROR_INVALID_HANDLE );
    TEST_EQUAL( psa_close_key( handle1 + 1 ), PSA_ERROR_INVALID_HANDLE );
    TEST_EQUAL( psa_destroy_key( 0 ), PSA_ERROR_INVALID_HANDLE );
    TEST_EQUAL( psa_destroy_key( handle1 - 1 ), PSA_ERROR_INVALID_HANDLE );
    TEST_EQUAL( psa_destroy_key( handle1 + 1 ), PSA_ERROR_INVALID_HANDLE );

    /* After all this, check that the original handle is intact. */
    PSA_ASSERT( psa_get_key_information( handle1, &read_type, &read_bits ) );
    TEST_EQUAL( read_type, PSA_KEY_TYPE_RAW_DATA );
    TEST_EQUAL( read_bits, PSA_BYTES_TO_BITS( sizeof( material ) ) );
    PSA_ASSERT( psa_close_key( handle1 ) );

exit:
    mbedtls_psa_crypto_free( );
}

void test_invalid_handle_wrapper( void ** params )
{
    (void)params;

    test_invalid_handle(  );
}
#line 692 "/home/ubuntu/work/git-repos/aws-iot-device-sdk-embedded-C/external_libs/mbedTLS/crypto/tests/suites/test_suite_psa_crypto_slot_management.function"
void test_many_transient_handles( int max_handles_arg )
{
    psa_key_handle_t *handles = NULL;
    size_t max_handles = max_handles_arg;
    size_t i, j;
    psa_status_t status;
    psa_key_policy_t policy = PSA_KEY_POLICY_INIT;
    uint8_t exported[sizeof( size_t )];
    size_t exported_length;

    ASSERT_ALLOC( handles, max_handles );
    PSA_ASSERT( psa_crypto_init( ) );
    psa_key_policy_set_usage( &policy, PSA_KEY_USAGE_EXPORT, 0 );

    for( i = 0; i < max_handles; i++ )
    {
        status = psa_allocate_key( &handles[i] );
        if( status == PSA_ERROR_INSUFFICIENT_MEMORY )
            break;
        PSA_ASSERT( status );
        TEST_ASSERT( handles[i] != 0 );
        for( j = 0; j < i; j++ )
            TEST_ASSERT( handles[i] != handles[j] );
        PSA_ASSERT( psa_set_key_policy( handles[i], &policy ) );
        PSA_ASSERT( psa_import_key( handles[i], PSA_KEY_TYPE_RAW_DATA,
                                    (uint8_t *) &i, sizeof( i ) ) );
    }
    max_handles = i;

    for( i = 1; i < max_handles; i++ )
    {
        PSA_ASSERT( psa_close_key( handles[i - 1] ) );
        PSA_ASSERT( psa_export_key( handles[i],
                                    exported, sizeof( exported ),
                                    &exported_length ) );
        ASSERT_COMPARE( exported, exported_length,
                        (uint8_t *) &i, sizeof( i ) );
    }
    PSA_ASSERT( psa_close_key( handles[i - 1] ) );

exit:
    mbedtls_psa_crypto_free( );
    mbedtls_free( handles );
}

void test_many_transient_handles_wrapper( void ** params )
{

    test_many_transient_handles( *( (int *) params[0] ) );
}
#endif /* MBEDTLS_PSA_CRYPTO_C */


#line 49 "suites/main_test.function"


/*----------------------------------------------------------------------------*/
/* Test dispatch code */


/**
 * \brief       Evaluates an expression/macro into its literal integer value.
 *              For optimizing space for embedded targets each expression/macro
 *              is identified by a unique identifier instead of string literals.
 *              Identifiers and evaluation code is generated by script:
 *              generate_test_code.py
 *
 * \param exp_id    Expression identifier.
 * \param out_value Pointer to int to hold the integer.
 *
 * \return       0 if exp_id is found. 1 otherwise.
 */
int get_expression( int32_t exp_id, int32_t * out_value )
{
    int ret = KEY_VALUE_MAPPING_FOUND;

    (void) exp_id;
    (void) out_value;

    switch( exp_id )
    {

#if defined(MBEDTLS_PSA_CRYPTO_C)

        case 0:
            {
                *out_value = PSA_KEY_TYPE_RAW_DATA;
            }
            break;
        case 1:
            {
                *out_value = CLOSE_BY_CLOSE;
            }
            break;
        case 2:
            {
                *out_value = CLOSE_BY_DESTROY;
            }
            break;
        case 3:
            {
                *out_value = CLOSE_BY_SHUTDOWN;
            }
            break;
        case 4:
            {
                *out_value = PSA_KEY_LIFETIME_PERSISTENT;
            }
            break;
        case 5:
            {
                *out_value = PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_SIGN | PSA_KEY_USAGE_VERIFY;
            }
            break;
        case 6:
            {
                *out_value = PSA_ALG_ECDSA_ANY;
            }
            break;
        case 7:
            {
                *out_value = PSA_KEY_TYPE_ECC_KEYPAIR(PSA_ECC_CURVE_SECP256R1);
            }
            break;
        case 8:
            {
                *out_value = PSA_ALG_ECDH(PSA_ALG_HKDF(PSA_ALG_SHA_256));
            }
            break;
        case 9:
            {
                *out_value = CLOSE_BEFORE;
            }
            break;
        case 10:
            {
                *out_value = CLOSE_AFTER;
            }
            break;
        case 11:
            {
                *out_value = KEEP_OPEN;
            }
            break;
        case 12:
            {
                *out_value = PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
        case 13:
            {
                *out_value = PSA_CRYPTO_ITS_RANDOM_SEED_UID;
            }
            break;
        case 14:
            {
                *out_value = PSA_ERROR_DOES_NOT_EXIST;
            }
            break;
        case 15:
            {
                *out_value = PSA_KEY_LIFETIME_VOLATILE;
            }
            break;
        case 16:
            {
                *out_value = PSA_ERROR_NOT_SUPPORTED;
            }
            break;
        case 17:
            {
                *out_value = PSA_KEY_USAGE_EXPORT;
            }
            break;
        case 18:
            {
                *out_value = PSA_ALG_CTR;
            }
            break;
        case 19:
            {
                *out_value = PSA_ALG_CBC_NO_PADDING;
            }
            break;
        case 20:
            {
                *out_value = PSA_KEY_TYPE_AES;
            }
            break;
#endif

#line 78 "suites/main_test.function"
        default:
           {
                ret = KEY_VALUE_MAPPING_NOT_FOUND;
           }
           break;
    }
    return( ret );
}


/**
 * \brief       Checks if the dependency i.e. the compile flag is set.
 *              For optimizing space for embedded targets each dependency
 *              is identified by a unique identifier instead of string literals.
 *              Identifiers and check code is generated by script:
 *              generate_test_code.py
 *
 * \param exp_id    Dependency identifier.
 *
 * \return       DEPENDENCY_SUPPORTED if set else DEPENDENCY_NOT_SUPPORTED
 */
int dep_check( int dep_id )
{
    int ret = DEPENDENCY_NOT_SUPPORTED;

    (void) dep_id;

    switch( dep_id )
    {

#if defined(MBEDTLS_PSA_CRYPTO_C)

        case 0:
            {
#if defined(MBEDTLS_ECDSA_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 1:
            {
#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 2:
            {
#if defined(MBEDTLS_ECDH_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 3:
            {
#if defined(MBEDTLS_SHA256_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 4:
            {
#if defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 5:
            {
#if !defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 6:
            {
#if defined(MBEDTLS_AES_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 7:
            {
#if defined(MBEDTLS_CIPHER_MODE_CTR)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 8:
            {
#if defined(MBEDTLS_CIPHER_MODE_CBC)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
#endif

#line 109 "suites/main_test.function"
        default:
            break;
    }
    return( ret );
}


/**
 * \brief       Function pointer type for test function wrappers.
 *
 *
 * \param void **   Pointer to void pointers. Represents an array of test
 *                  function parameters.
 *
 * \return       void
 */
typedef void (*TestWrapper_t)( void ** );


/**
 * \brief       Table of test function wrappers. Used by dispatch_test().
 *              This table is populated by script:
 *              generate_test_code.py
 *
 */
TestWrapper_t test_funcs[] =
{
/* Function Id: 0 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_transient_slot_lifecycle_wrapper,
#else
    NULL,
#endif
/* Function Id: 1 */

#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
    test_persistent_slot_lifecycle_wrapper,
#else
    NULL,
#endif
/* Function Id: 2 */

#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
    test_create_existent_wrapper,
#else
    NULL,
#endif
/* Function Id: 3 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_open_fail_wrapper,
#else
    NULL,
#endif
/* Function Id: 4 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_create_fail_wrapper,
#else
    NULL,
#endif
/* Function Id: 5 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_copy_across_lifetimes_wrapper,
#else
    NULL,
#endif
/* Function Id: 6 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_copy_from_empty_wrapper,
#else
    NULL,
#endif
/* Function Id: 7 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_copy_to_occupied_wrapper,
#else
    NULL,
#endif
/* Function Id: 8 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_copy_to_same_wrapper,
#else
    NULL,
#endif
/* Function Id: 9 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_invalid_handle_wrapper,
#else
    NULL,
#endif
/* Function Id: 10 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_many_transient_handles_wrapper,
#else
    NULL,
#endif

#line 138 "suites/main_test.function"
};

/**
 * \brief        Execute the test function.
 *
 *               This is a wrapper function around the test function execution
 *               to allow the setjmp() call used to catch any calls to the
 *               parameter failure callback, to be used. Calls to setjmp()
 *               can invalidate the state of any local auto variables.
 *
 * \param fp     Function pointer to the test function
 * \param params Parameters to pass
 *
 */
void execute_function_ptr(TestWrapper_t fp, void **params)
{
#if defined(MBEDTLS_CHECK_PARAMS)
    if ( setjmp( param_fail_jmp ) == 0 )
    {
        fp( params );
    }
    else
    {
        /* Unexpected parameter validation error */
        test_info.failed = 1;
    }

    memset( param_fail_jmp, 0, sizeof(jmp_buf) );
#else
    fp( params );
#endif
}

/**
 * \brief        Dispatches test functions based on function index.
 *
 * \param exp_id    Test function index.
 *
 * \return       DISPATCH_TEST_SUCCESS if found
 *               DISPATCH_TEST_FN_NOT_FOUND if not found
 *               DISPATCH_UNSUPPORTED_SUITE if not compile time enabled.
 */
int dispatch_test( int func_idx, void ** params )
{
    int ret = DISPATCH_TEST_SUCCESS;
    TestWrapper_t fp = NULL;

    if ( func_idx < (int)( sizeof( test_funcs ) / sizeof( TestWrapper_t ) ) )
    {
        fp = test_funcs[func_idx];
        if ( fp )
            execute_function_ptr(fp, params);
        else
            ret = DISPATCH_UNSUPPORTED_SUITE;
    }
    else
    {
        ret = DISPATCH_TEST_FN_NOT_FOUND;
    }

    return( ret );
}


/**
 * \brief       Checks if test function is supported
 *
 * \param exp_id    Test function index.
 *
 * \return       DISPATCH_TEST_SUCCESS if found
 *               DISPATCH_TEST_FN_NOT_FOUND if not found
 *               DISPATCH_UNSUPPORTED_SUITE if not compile time enabled.
 */
int check_test( int func_idx )
{
    int ret = DISPATCH_TEST_SUCCESS;
    TestWrapper_t fp = NULL;

    if ( func_idx < (int)( sizeof(test_funcs)/sizeof( TestWrapper_t ) ) )
    {
        fp = test_funcs[func_idx];
        if ( fp == NULL )
            ret = DISPATCH_UNSUPPORTED_SUITE;
    }
    else
    {
        ret = DISPATCH_TEST_FN_NOT_FOUND;
    }

    return( ret );
}


#line 2 "suites/host_test.function"

/**
 * \brief       Verifies that string is in string parameter format i.e. "<str>"
 *              It also strips enclosing '"' from the input string.
 *
 * \param str   String parameter.
 *
 * \return      0 if success else 1
 */
int verify_string( char **str )
{
    if( ( *str )[0] != '"' ||
        ( *str )[strlen( *str ) - 1] != '"' )
    {
        mbedtls_fprintf( stderr,
            "Expected string (with \"\") for parameter and got: %s\n", *str );
        return( -1 );
    }

    ( *str )++;
    ( *str )[strlen( *str ) - 1] = '\0';

    return( 0 );
}

/**
 * \brief       Verifies that string is an integer. Also gives the converted
 *              integer value.
 *
 * \param str   Input string.
 * \param value Pointer to int for output value.
 *
 * \return      0 if success else 1
 */
int verify_int( char *str, int *value )
{
    size_t i;
    int minus = 0;
    int digits = 1;
    int hex = 0;

    for( i = 0; i < strlen( str ); i++ )
    {
        if( i == 0 && str[i] == '-' )
        {
            minus = 1;
            continue;
        }

        if( ( ( minus && i == 2 ) || ( !minus && i == 1 ) ) &&
            str[i - 1] == '0' && ( str[i] == 'x' || str[i] == 'X' ) )
        {
            hex = 1;
            continue;
        }

        if( ! ( ( str[i] >= '0' && str[i] <= '9' ) ||
                ( hex && ( ( str[i] >= 'a' && str[i] <= 'f' ) ||
                           ( str[i] >= 'A' && str[i] <= 'F' ) ) ) ) )
        {
            digits = 0;
            break;
        }
    }

    if( digits )
    {
        if( hex )
            *value = strtol( str, NULL, 16 );
        else
            *value = strtol( str, NULL, 10 );

        return( 0 );
    }

    mbedtls_fprintf( stderr,
                    "Expected integer for parameter and got: %s\n", str );
    return( KEY_VALUE_MAPPING_NOT_FOUND );
}


/**
 * \brief       Usage string.
 *
 */
#define USAGE \
    "Usage: %s [OPTIONS] files...\n\n" \
    "   Command line arguments:\n" \
    "     files...          One or more test data files. If no file is\n" \
    "                       specified the following default test case\n" \
    "                       file is used:\n" \
    "                           %s\n\n" \
    "   Options:\n" \
    "     -v | --verbose    Display full information about each test\n" \
    "     -h | --help       Display this information\n\n", \
    argv[0], \
    "TESTCASE_FILENAME"


/**
 * \brief       Read a line from the passed file pointer.
 *
 * \param f     FILE pointer
 * \param buf   Pointer to memory to hold read line.
 * \param len   Length of the buf.
 *
 * \return      0 if success else -1
 */
int get_line( FILE *f, char *buf, size_t len )
{
    char *ret;
    int i = 0, str_len = 0, has_string = 0;

    /* Read until we get a valid line */
    do
    {
        ret = fgets( buf, len, f );
        if( ret == NULL )
            return( -1 );

        str_len = strlen( buf );

        /* Skip empty line and comment */
        if ( str_len == 0 || buf[0] == '#' )
            continue;
        has_string = 0;
        for ( i = 0; i < str_len; i++ )
        {
            char c = buf[i];
            if ( c != ' ' && c != '\t' && c != '\n' &&
                 c != '\v' && c != '\f' && c != '\r' )
            {
                has_string = 1;
                break;
            }
        }
    } while( !has_string );

    /* Strip new line and carriage return */
    ret = buf + strlen( buf );
    if( ret-- > buf && *ret == '\n' )
        *ret = '\0';
    if( ret-- > buf && *ret == '\r' )
        *ret = '\0';

    return( 0 );
}

/**
 * \brief       Splits string delimited by ':'. Ignores '\:'.
 *
 * \param buf           Input string
 * \param len           Input string length
 * \param params        Out params found
 * \param params_len    Out params array len
 *
 * \return      Count of strings found.
 */
static int parse_arguments( char *buf, size_t len, char **params,
                            size_t params_len )
{
    size_t cnt = 0, i;
    char *cur = buf;
    char *p = buf, *q;

    params[cnt++] = cur;

    while( *p != '\0' && p < ( buf + len ) )
    {
        if( *p == '\\' )
        {
            p++;
            p++;
            continue;
        }
        if( *p == ':' )
        {
            if( p + 1 < buf + len )
            {
                cur = p + 1;
                TEST_HELPER_ASSERT( cnt < params_len );
                params[cnt++] = cur;
            }
            *p = '\0';
        }

        p++;
    }

    /* Replace newlines, question marks and colons in strings */
    for( i = 0; i < cnt; i++ )
    {
        p = params[i];
        q = params[i];

        while( *p != '\0' )
        {
            if( *p == '\\' && *( p + 1 ) == 'n' )
            {
                p += 2;
                *( q++ ) = '\n';
            }
            else if( *p == '\\' && *( p + 1 ) == ':' )
            {
                p += 2;
                *( q++ ) = ':';
            }
            else if( *p == '\\' && *( p + 1 ) == '?' )
            {
                p += 2;
                *( q++ ) = '?';
            }
            else
                *( q++ ) = *( p++ );
        }
        *q = '\0';
    }

    return( cnt );
}

/**
 * \brief       Converts parameters into test function consumable parameters.
 *              Example: Input:  {"int", "0", "char*", "Hello",
 *                                "hex", "abef", "exp", "1"}
 *                      Output:  {
 *                                0,                // Verified int
 *                                "Hello",          // Verified string
 *                                2, { 0xab, 0xef },// Converted len,hex pair
 *                                9600              // Evaluated expression
 *                               }
 *
 *
 * \param cnt               Parameter array count.
 * \param params            Out array of found parameters.
 * \param int_params_store  Memory for storing processed integer parameters.
 *
 * \return      0 for success else 1
 */
static int convert_params( size_t cnt , char ** params , int * int_params_store )
{
    char ** cur = params;
    char ** out = params;
    int ret = DISPATCH_TEST_SUCCESS;

    while ( cur < params + cnt )
    {
        char * type = *cur++;
        char * val = *cur++;

        if ( strcmp( type, "char*" ) == 0 )
        {
            if ( verify_string( &val ) == 0 )
            {
              *out++ = val;
            }
            else
            {
                ret = ( DISPATCH_INVALID_TEST_DATA );
                break;
            }
        }
        else if ( strcmp( type, "int" ) == 0 )
        {
            if ( verify_int( val, int_params_store ) == 0 )
            {
              *out++ = (char *) int_params_store++;
            }
            else
            {
                ret = ( DISPATCH_INVALID_TEST_DATA );
                break;
            }
        }
        else if ( strcmp( type, "hex" ) == 0 )
        {
            if ( verify_string( &val ) == 0 )
            {
                *int_params_store = unhexify( (unsigned char *) val, val );
                *out++ = val;
                *out++ = (char *)(int_params_store++);
            }
            else
            {
                ret = ( DISPATCH_INVALID_TEST_DATA );
                break;
            }
        }
        else if ( strcmp( type, "exp" ) == 0 )
        {
            int exp_id = strtol( val, NULL, 10 );
            if ( get_expression ( exp_id, int_params_store ) == 0 )
            {
              *out++ = (char *)int_params_store++;
            }
            else
            {
              ret = ( DISPATCH_INVALID_TEST_DATA );
              break;
            }
        }
        else
        {
          ret = ( DISPATCH_INVALID_TEST_DATA );
          break;
        }
    }
    return( ret );
}

/**
 * \brief       Tests snprintf implementation with test input.
 *
 * \note
 * At high optimization levels (e.g. gcc -O3), this function may be
 * inlined in run_test_snprintf. This can trigger a spurious warning about
 * potential misuse of snprintf from gcc -Wformat-truncation (observed with
 * gcc 7.2). This warning makes tests in run_test_snprintf redundant on gcc
 * only. They are still valid for other compilers. Avoid this warning by
 * forbidding inlining of this function by gcc.
 *
 * \param n         Buffer test length.
 * \param ref_buf   Expected buffer.
 * \param ref_ret   Expected snprintf return value.
 *
 * \return      0 for success else 1
 */
#if defined(__GNUC__)
__attribute__((__noinline__))
#endif
static int test_snprintf( size_t n, const char ref_buf[10], int ref_ret )
{
    int ret;
    char buf[10] = "xxxxxxxxx";
    const char ref[10] = "xxxxxxxxx";

    if( n >= sizeof( buf ) )
        return( -1 );
    ret = mbedtls_snprintf( buf, n, "%s", "123" );
    if( ret < 0 || (size_t) ret >= n )
        ret = -1;

    if( strncmp( ref_buf, buf, sizeof( buf ) ) != 0 ||
        ref_ret != ret ||
        memcmp( buf + n, ref + n, sizeof( buf ) - n ) != 0 )
    {
        return( 1 );
    }

    return( 0 );
}

/**
 * \brief       Tests snprintf implementation.
 *
 * \param none
 *
 * \return      0 for success else 1
 */
static int run_test_snprintf( void )
{
    return( test_snprintf( 0, "xxxxxxxxx",  -1 ) != 0 ||
            test_snprintf( 1, "",           -1 ) != 0 ||
            test_snprintf( 2, "1",          -1 ) != 0 ||
            test_snprintf( 3, "12",         -1 ) != 0 ||
            test_snprintf( 4, "123",         3 ) != 0 ||
            test_snprintf( 5, "123",         3 ) != 0 );
}


/**
 * \brief       Desktop implementation of execute_tests().
 *              Parses command line and executes tests from
 *              supplied or default data file.
 *
 * \param argc  Command line argument count.
 * \param argv  Argument array.
 *
 * \return      Program exit status.
 */
int execute_tests( int argc , const char ** argv )
{
    /* Local Configurations and options */
    const char *default_filename = "./test_suite_psa_crypto_slot_management.datax";
    const char *test_filename = NULL;
    const char **test_files = NULL;
    int testfile_count = 0;
    int option_verbose = 0;
    int function_id = 0;

    /* Other Local variables */
    int arg_index = 1;
    const char *next_arg;
    int testfile_index, ret, i, cnt;
    int total_errors = 0, total_tests = 0, total_skipped = 0;
    FILE *file;
    char buf[5000];
    char *params[50];
    /* Store for proccessed integer params. */
    int int_params[50];
    void *pointer;
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
    int stdout_fd = -1;
#endif /* __unix__ || __APPLE__ __MACH__ */

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && \
    !defined(TEST_SUITE_MEMORY_BUFFER_ALLOC)
    unsigned char alloc_buf[1000000];
    mbedtls_memory_buffer_alloc_init( alloc_buf, sizeof( alloc_buf ) );
#endif

    /*
     * The C standard doesn't guarantee that all-bits-0 is the representation
     * of a NULL pointer. We do however use that in our code for initializing
     * structures, which should work on every modern platform. Let's be sure.
     */
    memset( &pointer, 0, sizeof( void * ) );
    if( pointer != NULL )
    {
        mbedtls_fprintf( stderr, "all-bits-zero is not a NULL pointer\n" );
        return( 1 );
    }

    /*
     * Make sure we have a snprintf that correctly zero-terminates
     */
    if( run_test_snprintf() != 0 )
    {
        mbedtls_fprintf( stderr, "the snprintf implementation is broken\n" );
        return( 1 );
    }

    while( arg_index < argc )
    {
        next_arg = argv[arg_index];

        if( strcmp( next_arg, "--verbose" ) == 0 ||
                 strcmp( next_arg, "-v" ) == 0 )
        {
            option_verbose = 1;
        }
        else if( strcmp(next_arg, "--help" ) == 0 ||
                 strcmp(next_arg, "-h" ) == 0 )
        {
            mbedtls_fprintf( stdout, USAGE );
            mbedtls_exit( EXIT_SUCCESS );
        }
        else
        {
            /* Not an option, therefore treat all further arguments as the file
             * list.
             */
            test_files = &argv[ arg_index ];
            testfile_count = argc - arg_index;
        }

        arg_index++;
    }

    /* If no files were specified, assume a default */
    if ( test_files == NULL || testfile_count == 0 )
    {
        test_files = &default_filename;
        testfile_count = 1;
    }

    /* Initialize the struct that holds information about the last test */
    memset( &test_info, 0, sizeof( test_info ) );

    /* Now begin to execute the tests in the testfiles */
    for ( testfile_index = 0;
          testfile_index < testfile_count;
          testfile_index++ )
    {
        int unmet_dep_count = 0;
        char *unmet_dependencies[20];

        test_filename = test_files[ testfile_index ];

        file = fopen( test_filename, "r" );
        if( file == NULL )
        {
            mbedtls_fprintf( stderr, "Failed to open test file: %s\n",
                             test_filename );
            return( 1 );
        }

        while( !feof( file ) )
        {
            if( unmet_dep_count > 0 )
            {
                mbedtls_fprintf( stderr,
                    "FATAL: Dep count larger than zero at start of loop\n" );
                mbedtls_exit( MBEDTLS_EXIT_FAILURE );
            }
            unmet_dep_count = 0;

            if( ( ret = get_line( file, buf, sizeof(buf) ) ) != 0 )
                break;
            mbedtls_fprintf( stdout, "%s%.66s", test_info.failed ? "\n" : "", buf );
            mbedtls_fprintf( stdout, " " );
            for( i = strlen( buf ) + 1; i < 67; i++ )
                mbedtls_fprintf( stdout, "." );
            mbedtls_fprintf( stdout, " " );
            fflush( stdout );

            total_tests++;

            if( ( ret = get_line( file, buf, sizeof( buf ) ) ) != 0 )
                break;
            cnt = parse_arguments( buf, strlen( buf ), params,
                                   sizeof( params ) / sizeof( params[0] ) );

            if( strcmp( params[0], "depends_on" ) == 0 )
            {
                for( i = 1; i < cnt; i++ )
                {
                    int dep_id = strtol( params[i], NULL, 10 );
                    if( dep_check( dep_id ) != DEPENDENCY_SUPPORTED )
                    {
                        if( 0 == option_verbose )
                        {
                            /* Only one count is needed if not verbose */
                            unmet_dep_count++;
                            break;
                        }

                        unmet_dependencies[ unmet_dep_count ] = strdup( params[i] );
                        if(  unmet_dependencies[ unmet_dep_count ] == NULL )
                        {
                            mbedtls_fprintf( stderr, "FATAL: Out of memory\n" );
                            mbedtls_exit( MBEDTLS_EXIT_FAILURE );
                        }
                        unmet_dep_count++;
                    }
                }

                if( ( ret = get_line( file, buf, sizeof( buf ) ) ) != 0 )
                    break;
                cnt = parse_arguments( buf, strlen( buf ), params,
                                       sizeof( params ) / sizeof( params[0] ) );
            }

            // If there are no unmet dependencies execute the test
            if( unmet_dep_count == 0 )
            {
                test_info.failed = 0;
                test_info.paramfail_test_state = PARAMFAIL_TESTSTATE_IDLE;

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
                /* Suppress all output from the library unless we're verbose
                 * mode
                 */
                if( !option_verbose )
                {
                    stdout_fd = redirect_output( &stdout, "/dev/null" );
                    if( stdout_fd == -1 )
                    {
                        /* Redirection has failed with no stdout so exit */
                        exit( 1 );
                    }
                }
#endif /* __unix__ || __APPLE__ __MACH__ */

                function_id = strtol( params[0], NULL, 10 );
                if ( (ret = check_test( function_id )) == DISPATCH_TEST_SUCCESS )
                {
                    ret = convert_params( cnt - 1, params + 1, int_params );
                    if ( DISPATCH_TEST_SUCCESS == ret )
                    {
                        ret = dispatch_test( function_id, (void **)( params + 1 ) );
                    }
                }

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
                if( !option_verbose && restore_output( &stdout, stdout_fd ) )
                {
                        /* Redirection has failed with no stdout so exit */
                        exit( 1 );
                }
#endif /* __unix__ || __APPLE__ __MACH__ */

            }

            if( unmet_dep_count > 0 || ret == DISPATCH_UNSUPPORTED_SUITE )
            {
                total_skipped++;
                mbedtls_fprintf( stdout, "----" );

                if( 1 == option_verbose && ret == DISPATCH_UNSUPPORTED_SUITE )
                {
                    mbedtls_fprintf( stdout, "\n   Test Suite not enabled" );
                }

                if( 1 == option_verbose && unmet_dep_count > 0 )
                {
                    mbedtls_fprintf( stdout, "\n   Unmet dependencies: " );
                    for( i = 0; i < unmet_dep_count; i++ )
                    {
                        mbedtls_fprintf( stdout, "%s  ",
                                        unmet_dependencies[i] );
                        free( unmet_dependencies[i] );
                    }
                }
                mbedtls_fprintf( stdout, "\n" );
                fflush( stdout );

                unmet_dep_count = 0;
            }
            else if( ret == DISPATCH_TEST_SUCCESS )
            {
                if( test_info.failed == 0 )
                {
                    mbedtls_fprintf( stdout, "PASS\n" );
                }
                else
                {
                    total_errors++;
                    mbedtls_fprintf( stdout, "FAILED\n" );
                    mbedtls_fprintf( stdout, "  %s\n  at line %d, %s\n",
                                     test_info.test, test_info.line_no,
                                     test_info.filename );
                }
                fflush( stdout );
            }
            else if( ret == DISPATCH_INVALID_TEST_DATA )
            {
                mbedtls_fprintf( stderr, "FAILED: FATAL PARSE ERROR\n" );
                fclose( file );
                mbedtls_exit( 2 );
            }
            else if( ret == DISPATCH_TEST_FN_NOT_FOUND )
            {
                mbedtls_fprintf( stderr, "FAILED: FATAL TEST FUNCTION NOT FUND\n" );
                fclose( file );
                mbedtls_exit( 2 );
            }
            else
                total_errors++;
        }
        fclose( file );

        /* In case we encounter early end of file */
        for( i = 0; i < unmet_dep_count; i++ )
            free( unmet_dependencies[i] );
    }

    mbedtls_fprintf( stdout, "\n----------------------------------------------------------------------------\n\n");
    if( total_errors == 0 )
        mbedtls_fprintf( stdout, "PASSED" );
    else
        mbedtls_fprintf( stdout, "FAILED" );

    mbedtls_fprintf( stdout, " (%d / %d tests (%d skipped))\n",
             total_tests - total_errors, total_tests, total_skipped );

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && \
    !defined(TEST_SUITE_MEMORY_BUFFER_ALLOC)
#if defined(MBEDTLS_MEMORY_DEBUG)
    mbedtls_memory_buffer_alloc_status();
#endif
    mbedtls_memory_buffer_alloc_free();
#endif

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
    if( stdout_fd != -1 )
        close_output( stdout );
#endif /* __unix__ || __APPLE__ __MACH__ */

    return( total_errors != 0 );
}


#line 234 "suites/main_test.function"

/*----------------------------------------------------------------------------*/
/* Main Test code */


/**
 * \brief       Program main. Invokes platform specific execute_tests().
 *
 * \param argc      Command line arguments count.
 * \param argv      Array of command line arguments.
 *
 * \return       Exit code.
 */
int main( int argc, const char *argv[] )
{
    int ret = platform_setup();
    if( ret != 0 )
    {
        mbedtls_fprintf( stderr,
                         "FATAL: Failed to initialize platform - error %d\n",
                         ret );
        return( -1 );
    }

    ret = execute_tests( argc, argv );
    platform_teardown();
    return( ret );
}
