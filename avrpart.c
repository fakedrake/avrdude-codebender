
/*
 * avrdude - A Downloader/Uploader for AVR device programmers
 * Copyright (C) 2000-2004  Brian S. Dean <bsd@bsdhome.com>
 * Copyright (C) 2006 Joerg Wunsch <j@uriah.heep.sax.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/* $Id: avrpart.c 1294 2014-03-12 23:03:18Z joerg_wunsch $ */

#include <stdlib.h>
#include <string.h>

#include "avrdude.h"
#include "avrpart.h"
#include "pindefs.h"

/***
 *** Elementary functions dealing with OPCODE structures
 ***/

OPCODE * avr_new_opcode(void)
{
    OPCODE * m;

    m = (OPCODE *)malloc(sizeof(*m));
    if (m == NULL) {
        fprintf(stderr, "avr_new_opcode(): out of memory\n");
        exit(1);
    }

    memset(m, 0, sizeof(*m));

    return m;
}

static OPCODE * avr_dup_opcode(OPCODE * op)
{
    OPCODE * m;

    /* this makes life easier */
    if (op == NULL) {
        return NULL;
    }

    m = (OPCODE *)malloc(sizeof(*m));
    if (m == NULL) {
        fprintf(stderr, "avr_dup_opcode(): out of memory\n");
        exit(1);
    }

    memcpy(m, op, sizeof(*m));

    return m;
}

void avr_free_opcode(OPCODE * op)
{
    free(op);
}

/*
 * avr_set_bits()
 *
 * Set instruction bits in the specified command based on the opcode.
 */
int avr_set_bits(OPCODE * op, unsigned char * cmd)
{
    int i, j, bit;
    unsigned char mask;

    for (i=0; i<32; i++) {
        if (op->bit[i].type == AVR_CMDBIT_VALUE) {
            j = 3 - i / 8;
            bit = i % 8;
            mask = 1 << bit;
            if (op->bit[i].value)
                cmd[j] = cmd[j] | mask;
            else
                cmd[j] = cmd[j] & ~mask;
        }
    }

    return 0;
}


/*
 * avr_set_addr()
 *
 * Set address bits in the specified command based on the opcode, and
 * the address.
 */
int avr_set_addr(OPCODE * op, unsigned char * cmd, unsigned long addr)
{
    int i, j, bit;
    unsigned long value;
    unsigned char mask;

    for (i=0; i<32; i++) {
        if (op->bit[i].type == AVR_CMDBIT_ADDRESS) {
            j = 3 - i / 8;
            bit = i % 8;
            mask = 1 << bit;
            value = addr >> op->bit[i].bitno & 0x01;
            if (value)
                cmd[j] = cmd[j] | mask;
            else
                cmd[j] = cmd[j] & ~mask;
        }
    }

    return 0;
}


/*
 * avr_set_input()
 *
 * Set input data bits in the specified command based on the opcode,
 * and the data byte.
 */
int avr_set_input(OPCODE * op, unsigned char * cmd, unsigned char data)
{
    int i, j, bit;
    unsigned char value;
    unsigned char mask;

    for (i=0; i<32; i++) {
        if (op->bit[i].type == AVR_CMDBIT_INPUT) {
            j = 3 - i / 8;
            bit = i % 8;
            mask = 1 << bit;
            value = data >> op->bit[i].bitno & 0x01;
            if (value)
                cmd[j] = cmd[j] | mask;
            else
                cmd[j] = cmd[j] & ~mask;
        }
    }

    return 0;
}


/*
 * avr_get_output()
 *
 * Retreive output data bits from the command results based on the
 * opcode data.
 */
int avr_get_output(OPCODE * op, unsigned char * res, unsigned char * data)
{
    int i, j, bit;
    unsigned char value;
    unsigned char mask;

    for (i=0; i<32; i++) {
        if (op->bit[i].type == AVR_CMDBIT_OUTPUT) {
            j = 3 - i / 8;
            bit = i % 8;
            mask = 1 << bit;
            value = ((res[j] & mask) >> bit) & 0x01;
            value = value << op->bit[i].bitno;
            if (value)
                *data = *data | value;
            else
                *data = *data & ~value;
        }
    }

    return 0;
}


/*
 * avr_get_output_index()
 *
 * Calculate the byte number of the output data based on the
 * opcode data.
 */
int avr_get_output_index(OPCODE * op)
{
    int i, j;

    for (i=0; i<32; i++) {
        if (op->bit[i].type == AVR_CMDBIT_OUTPUT) {
            j = 3 - i / 8;
            return j;
        }
    }

    return -1;
}


static char * avr_op_str(int op)
{
    switch (op) {
    case AVR_OP_READ        : return "READ"; break;
    case AVR_OP_WRITE       : return "WRITE"; break;
    case AVR_OP_READ_LO     : return "READ_LO"; break;
    case AVR_OP_READ_HI     : return "READ_HI"; break;
    case AVR_OP_WRITE_LO    : return "WRITE_LO"; break;
    case AVR_OP_WRITE_HI    : return "WRITE_HI"; break;
    case AVR_OP_LOADPAGE_LO : return "LOADPAGE_LO"; break;
    case AVR_OP_LOADPAGE_HI : return "LOADPAGE_HI"; break;
    case AVR_OP_LOAD_EXT_ADDR : return "LOAD_EXT_ADDR"; break;
    case AVR_OP_WRITEPAGE   : return "WRITEPAGE"; break;
    case AVR_OP_CHIP_ERASE  : return "CHIP_ERASE"; break;
    case AVR_OP_PGM_ENABLE  : return "PGM_ENABLE"; break;
    default : return "<unknown opcode>"; break;
    }
}


static char * bittype(int type)
{
    switch (type) {
    case AVR_CMDBIT_IGNORE  : return "IGNORE"; break;
    case AVR_CMDBIT_VALUE   : return "VALUE"; break;
    case AVR_CMDBIT_ADDRESS : return "ADDRESS"; break;
    case AVR_CMDBIT_INPUT   : return "INPUT"; break;
    case AVR_CMDBIT_OUTPUT  : return "OUTPUT"; break;
    default : return "<unknown bit type>"; break;
    }
}



/***
 *** Elementary functions dealing with AVRMEM structures
 ***/

AVRMEM * avr_new_memtype(void)
{
    AVRMEM * m;

    m = (AVRMEM *)malloc(sizeof(*m));
    if (m == NULL) {
        fprintf(stderr, "avr_new_memtype(): out of memory\n");
        exit(1);
    }

    memset(m, 0, sizeof(*m));

    return m;
}


/*
 * Allocate and initialize memory buffers for each of the device's
 * defined memory regions.
 */
int avr_initmem(AVRPART * p)
{
    LNODEID ln;
    AVRMEM * m;

    for (ln=lfirst(p->mem); ln; ln=lnext(ln)) {
        m = ldata(ln);
        m->buf = (unsigned char *) malloc(m->size);
        if (m->buf == NULL) {
            fprintf(stderr, "%s: can't alloc buffer for %s size of %d bytes\n",
                    progname, m->desc, m->size);
            return -1;
        }
        m->tags = (unsigned char *) malloc(m->size);
        if (m->tags == NULL) {
            fprintf(stderr, "%s: can't alloc buffer for %s size of %d bytes\n",
                    progname, m->desc, m->size);
            return -1;
        }
    }

    return 0;
}


AVRMEM * avr_dup_mem(AVRMEM * m)
{
    AVRMEM * n;
    int i;

    n = avr_new_memtype();

    *n = *m;

    if (m->buf != NULL) {
        n->buf = (unsigned char *)malloc(n->size);
        if (n->buf == NULL) {
            fprintf(stderr,
                    "avr_dup_mem(): out of memory (memsize=%d)\n",
                    n->size);
            exit(1);
        }
        memcpy(n->buf, m->buf, n->size);
    }

    if (m->tags != NULL) {
        n->tags = (unsigned char *)malloc(n->size);
        if (n->tags == NULL) {
            fprintf(stderr,
                    "avr_dup_mem(): out of memory (memsize=%d)\n",
                    n->size);
            exit(1);
        }
        memcpy(n->tags, m->tags, n->size);
    }

    for (i = 0; i < AVR_OP_MAX; i++) {
        n->op[i] = avr_dup_opcode(n->op[i]);
    }

    return n;
}

void avr_free_mem(AVRMEM * m)
{
    int i;
    if (m->buf != NULL) {
        free(m->buf);
        m->buf = NULL;
    }
    if (m->tags != NULL) {
        free(m->tags);
        m->tags = NULL;
    }
    for(i=0;i<sizeof(m->op)/sizeof(m->op[0]);i++)
    {
        if (m->op[i] != NULL)
        {
            avr_free_opcode(m->op[i]);
            m->op[i] = NULL;
        }
    }
    free(m);
}

AVRMEM * avr_locate_mem(AVRPART * p, char * desc)
{
    AVRMEM * m, * match;
    LNODEID ln;
    int matches;
    int l;

    l = strlen(desc);
    matches = 0;
    match = NULL;
    for (ln=lfirst(p->mem); ln; ln=lnext(ln)) {
        m = ldata(ln);
        if (strncmp(desc, m->desc, l) == 0) {
            match = m;
            matches++;
        }
    }

    if (matches == 1)
        return match;

    return NULL;
}


void show_op_array(FILE * f, const char * prefix, OPCODE ** oa)
{
    int i, j;
    char * optr;

    for (i=0; i<AVR_OP_MAX; i++) {
        if (oa[i]) {
            optr = avr_op_str(i);
            fprintf(f, "%s%s:[\n", prefix, optr);
            for (j=31; j>=0; j--) {
                fprintf(f, "%s{\n",prefix);
                fprintf(f, "%s\top: \"%s\",\n", prefix, optr);
                fprintf(f, "%s\tinstBit: %8d,\n", prefix, j);
                fprintf(f, "%s\tbitType: \"%s\",\n", prefix, bittype(oa[i]->bit[j].type));
                fprintf(f, "%s\tbitNo: %5d,\n", prefix,oa[i]->bit[j].bitno);
                fprintf(f, "%s\tvalue: %5d\n", prefix, oa[i]->bit[j].value);
                fprintf(f, "%s},\n", prefix);
            }
            fprintf(f, "%s],\n", prefix);
        }
    }
}

void avr_mem_display(const char * prefix, FILE * f, AVRMEM * m, int type,
                     int verbose)
{
    if (m == NULL) {
        /* fprintf(f, */
        /*         "%s                       Block Poll               Page                       Polled\n" */
        /*         "%sMemory Type Mode Delay Size  Indx Paged  Size   Size #Pages MinW  MaxW   ReadBack\n" */
        /*         "%s----------- ---- ----- ----- ---- ------ ------ ---- ------ ----- ----- ---------\n", */
        /*         prefix, prefix, prefix); */
    }
    else {
        fprintf(f, "%s: {\n",  m->desc);
        if ( m->mode) fprintf(f, "%smode: %4d,\n", prefix, m->mode);
        if ( m->delay) fprintf(f, "%sdelay: %5d,\n", prefix, m->delay);
        if ( m->blocksize) fprintf(f, "%sblocksize: %5d,\n", prefix, m->blocksize);
        if ( m->pollindex) fprintf(f, "%spollindex: %4d,\n", prefix, m->pollindex);
        fprintf(f, "%spaged: %-6s,\n", prefix, m->paged ? "true" : "false");
        if ( m->size) fprintf(f, "%ssize: %6d,\n", prefix, m->size);
        if ( m->page_size) fprintf(f, "%spage_size: %4d,\n", prefix, m->page_size);
        if ( m->num_pages) fprintf(f, "%snum_pages: %6d,\n", prefix, m->num_pages);
        if ( m->min_write_delay) fprintf(f, "%smin_write_delay: %5d,\n", prefix, m->min_write_delay);
        if ( m->max_write_delay) fprintf(f, "%smax_write_delay: %5d,\n", prefix, m->max_write_delay);
        fprintf(f, "%sreadback: [0x%02x, 0x%02x],\n", prefix, m->readback[0], m->readback[1]);
        /* fprintf(stderr, */
        /*         "%s  Memory Ops:\n" */
        /*         "%s    Oeration     Inst Bit  Bit Type  Bitno  Value\n" */
        /*         "%s    -----------  --------  --------  -----  -----\n", */
        /*         prefix, prefix, prefix); */
        fprintf(f, "%smemops: {\n", prefix);
        show_op_array(f, prefix, m->op);
        fprintf(f, "%s}\n", prefix);
        fprintf(f, "%s},\n", prefix);
    }
}



/*
 * Elementary functions dealing with AVRPART structures
 */


AVRPART * avr_new_part(void)
{
    AVRPART * p;

    p = (AVRPART *)malloc(sizeof(AVRPART));
    if (p == NULL) {
        fprintf(stderr, "new_part(): out of memory\n");
        exit(1);
    }

    memset(p, 0, sizeof(*p));

    p->id[0]   = 0;
    p->desc[0] = 0;
    p->reset_disposition = RESET_DEDICATED;
    p->retry_pulse = PIN_AVR_SCK;
    p->flags = AVRPART_SERIALOK | AVRPART_PARALLELOK | AVRPART_ENABLEPAGEPROGRAMMING;
    p->config_file[0] = 0;
    p->lineno = 0;
    memset(p->signature, 0xFF, 3);
    p->ctl_stack_type = CTL_STACK_NONE;
    p->ocdrev = -1;

    p->mem = lcreat(NULL, 0);

    return p;
}


AVRPART * avr_dup_part(AVRPART * d)
{
    AVRPART * p;
    LISTID save;
    LNODEID ln;
    int i;

    p = avr_new_part();
    save = p->mem;

    *p = *d;

    p->mem = save;

    for (ln=lfirst(d->mem); ln; ln=lnext(ln)) {
        ladd(p->mem, avr_dup_mem(ldata(ln)));
    }

    for (i = 0; i < AVR_OP_MAX; i++) {
        p->op[i] = avr_dup_opcode(p->op[i]);
    }

    return p;
}

void avr_free_part(AVRPART * d)
{
    int i;
    ldestroy_cb(d->mem, (void(*)(void *))avr_free_mem);
    d->mem = NULL;
    for(i=0;i<sizeof(d->op)/sizeof(d->op[0]);i++)
    {
        if (d->op[i] != NULL)
        {
            avr_free_opcode(d->op[i]);
            d->op[i] = NULL;
        }
    }
    free(d);
}

AVRPART * locate_part(LISTID parts, char * partdesc)
{
    LNODEID ln1;
    AVRPART * p = NULL;
    int found;

    found = 0;

    for (ln1=lfirst(parts); ln1 && !found; ln1=lnext(ln1)) {
        p = ldata(ln1);
        if ((strcasecmp(partdesc, p->id) == 0) ||
            (strcasecmp(partdesc, p->desc) == 0))
            found = 1;
    }

    if (found)
        return p;

    return NULL;
}

AVRPART * locate_part_by_avr910_devcode(LISTID parts, int devcode)
{
    LNODEID ln1;
    AVRPART * p = NULL;

    for (ln1=lfirst(parts); ln1; ln1=lnext(ln1)) {
        p = ldata(ln1);
        if (p->avr910_devcode == devcode)
            return p;
    }

    return NULL;
}

/*
 * Iterate over the list of avrparts given as "avrparts", and
 * call the callback function cb for each entry found.  cb is being
 * passed the following arguments:
 * . the name of the avrpart (for -p)
 * . the descriptive text given in the config file
 * . the name of the config file this avrpart has been defined in
 * . the line number of the config file this avrpart has been defined at
 * . the "cookie" passed into walk_avrparts() (opaque client data)
 */
void walk_avrparts(LISTID avrparts, walk_avrparts_cb cb, void *cookie)
{
    LNODEID ln1;
    AVRPART * p;

    for (ln1 = lfirst(avrparts); ln1; ln1 = lnext(ln1)) {
        p = ldata(ln1);
        ((struct list_walk_cookie *)cookie)->obj = (void*)p;
        cb(p->id, p->desc, p->config_file, p->lineno, cookie);
    }
}

/*
 * Compare function to sort the list of programmers
 */
static int sort_avrparts_compare(AVRPART * p1,AVRPART * p2)
{
    if(p1 == NULL || p2 == NULL) {
        return 0;
    }
    return strncasecmp(p1->desc,p2->desc,AVR_DESCLEN);
}

/*
 * Sort the list of programmers given as "programmers"
 */
void sort_avrparts(LISTID avrparts)
{
    lsort(avrparts,(int (*)(void*, void*)) sort_avrparts_compare);
}


static char * reset_disp_str(int r)
{
    switch (r) {
    case RESET_DEDICATED : return "dedicated";
    case RESET_IO        : return "possible i/o";
    default              : return "<invalid>";
    }
}


void avr_display(FILE * f, AVRPART * p, const char * prefix, int verbose)
{
    int i;
    char * buf;
    const char * px;
    LNODEID ln;
    AVRMEM * m;

    fprintf(f,"{\n");
    fprintf(f, "%sAVRPart: \"%s\",\n", prefix, p->desc);           /* AvrPart */
    if ( p->chip_erase_delay) if ( p->chip_erase_delay) fprintf(f, "%schipEraseDelay : %d,\n", prefix, p->chip_erase_delay);
    fprintf(f, "%sstk500_devcode : 0x%02x,\n", prefix, p->stk500_devcode);
    if ( p->pagel) fprintf(f, "%spagel : 0x%02x,\n", prefix, p->pagel);
    if ( p->bs2) fprintf(f, "%sbs2 : 0x%02x,\n", prefix, p->bs2);
    fprintf(f, "%sresetDisposition : \"%s\",\n", prefix, reset_disp_str(p->reset_disposition));
    fprintf(f, "%sretryPulse : \"%s\",\n", prefix, avr_pin_name(p->retry_pulse));
    /* Signature */
    fprintf(f, "%ssignature: [", prefix);
    int js; for (js = 0; js < 3; js++) fprintf(f, "0x%x,", p->signature[js]);
    fprintf(f, "],\n");

    fprintf(f, "%susbpid: 0x%x,\n", prefix, p->usbpid);

    fprintf
        (f, "%sserialProgramMode : %s,\n", prefix, (p->flags & AVRPART_SERIALOK) ? "true" : "false");
    fprintf(f, "%sparallelProgramMode : %s,\n", prefix, (p->flags & AVRPART_PARALLELOK)?"true":"false" );
    fprintf(f, "%spseudoparallelProgramMode : %s,\n", prefix, (p->flags & AVRPART_PSEUDOPARALLEL)?"true":"false" );
    fprintf(f, "%shasTpi: %s,\n", prefix, (p->flags & AVRPART_HAS_TPI) ? "true":"false" );
    fprintf(f, "%sisAvr32: %s,\n", prefix, (p->flags & AVRPART_AVR32) ? "true":"false" );
    fprintf(f, "%shasDebugWire: %s,\n", prefix, (p->flags & AVRPART_HAS_DW) ? "true":"false" );
    fprintf(f, "%shasWriteOperation: %s,\n", prefix, (p->flags & AVRPART_WRITE) ? "true":"false" );
    fprintf(f, "%shasJtag: %s,\n", prefix, (p->flags & AVRPART_HAS_JTAG) ? "true":"false" );
    fprintf(f, "%shasPdi: %s,\n", prefix, (p->flags & AVRPART_HAS_PDI) ? "true":"false" );
    fprintf(f, "%shasEnablePageProgramming: %s,\n", prefix, (p->flags & AVRPART_ENABLEPAGEPROGRAMMING) ? "true":"false" );
    fprintf(f, "%sallowFullPageBitstream: %s,\n", prefix, (p->flags & AVRPART_ALLOWFULLPAGEBITSTREAM) ? "true":"false" );
    fprintf(f, "%sallowInitSmc: %s,\n", prefix, (p->flags & AVRPART_INIT_SMC) ? "true":"false" );
    fprintf(f, "%sisAT90S1200: %s,\n", prefix, (p->flags & AVRPART_IS_AT90S1200) ? "true":"false" );

    if ( p->timeout) fprintf(f, "%stimeout : %d,\n", prefix, p->timeout);
    if ( p->stabdelay) fprintf(f, "%sstabDelay : %d,\n", prefix, p->stabdelay);
    if ( p->cmdexedelay) fprintf(f, "%scmdExeDelay : %d,\n", prefix, p->cmdexedelay);
    if ( p->synchloops) fprintf(f, "%ssyncLoops : %d,\n", prefix, p->synchloops);
    if ( p->bytedelay) fprintf(f, "%sbyteDelay : %d,\n", prefix, p->bytedelay);
    if ( p->pollindex) fprintf(f, "%spollIndex : %d,\n", prefix, p->pollindex);
    if ( p->pollvalue) fprintf(f, "%spollValue : 0x%02x,\n", prefix, p->pollvalue);
    if ( p->predelay) fprintf(f, "%spredelay: %d,\n", prefix, p->predelay);
    if ( p->pollmethod) fprintf(f, "%spollmethod: %d,\n", prefix, p->pollmethod);
    if ( p->postdelay) fprintf(f, "%spostdelay: %d,\n", prefix, p->postdelay);

    fprintf(f, "%shventerstabdelay: %d,\n", prefix, p->hventerstabdelay);
    fprintf(f, "%sprogmodedelay: %d,\n", prefix, p->progmodedelay);
    fprintf(f, "%slatchcycles: %d,\n", prefix, p->latchcycles);
    fprintf(f, "%stogglevtg: %d,\n", prefix, p->togglevtg);
    fprintf(f, "%spoweroffdelay: %d,\n", prefix, p->poweroffdelay);
    fprintf(f, "%sresetdelayms: %d,\n", prefix, p->resetdelayms);
    fprintf(f, "%sresetdelayus: %d,\n", prefix, p->resetdelayus);
    fprintf(f, "%shvleavestabdelay: %d,\n", prefix, p->hvleavestabdelay);
    fprintf(f, "%sresetdelay: %d,\n", prefix, p->resetdelay);
    fprintf(f, "%schiperasepulsewidth: %d,\n", prefix, p->chiperasepulsewidth);
    fprintf(f, "%schiperasepolltimeout: %d,\n", prefix, p->chiperasepolltimeout);
    fprintf(f, "%schiperasetime: %d,\n", prefix, p->chiperasetime);
    fprintf(f, "%sprogramfusepulsewidth: %d,\n", prefix, p->programfusepulsewidth);
    fprintf(f, "%sprogramfusepolltimeout: %d,\n", prefix, p->programfusepolltimeout);
    fprintf(f, "%sprogramlockpulsewidth: %d,\n", prefix, p->programlockpulsewidth);
    fprintf(f, "%sprogramlockpolltimeout: %d,\n", prefix, p->programlockpolltimeout);
    fprintf(f, "%ssynchcycles: %d,\n", prefix, p->synchcycles);
    fprintf(f, "%shvspcmdexedelay: %d,\n", prefix, p->hvspcmdexedelay);
    fprintf(f, "%sidr: %d,\n", prefix, p->idr);
    fprintf(f, "%srampz: %d,\n", prefix, p->rampz);
    fprintf(f, "%sspmcr: %d,\n", prefix, p->spmcr);
    fprintf(f, "%seecr: %d,\n", prefix, p->eecr);
    fprintf(f, "%socdrev: %d,\n", prefix, p->ocdrev);

    if ( p->op) {
        fprintf(f, "%sops : {\n", prefix);
        show_op_array(f, prefix, p->op);
        fprintf(f, "%s},\n", prefix);
    }
    fprintf(f, "%smemory :{\n", prefix);
    px = prefix;
    i = strlen(prefix) + 5;
    buf = (char *)malloc(i);
    if (buf == NULL) {
        /* ugh, this is not important enough to bail, just ignore it */
    }
    else {
        strcpy(buf, prefix);
        strcat(buf, "  ");
        px = buf;
    }

    if (verbose <= 2) {
        avr_mem_display(px, f, NULL, 0, verbose);
    }
    for (ln=lfirst(p->mem); ln; ln=lnext(ln)) {
        m = ldata(ln);
        avr_mem_display(px, f, m, i, verbose);
    }
    fprintf(f, "%s}\n", prefix);
    fprintf(f, "%s},\n", prefix);
    if (buf)
        free(buf);
}
