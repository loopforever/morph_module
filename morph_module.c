/*
    Morph Module - A Linux LKM for altering setuid behavior
    Copyright (C) 2011 Matt Savona

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

    ------------------

    This module is extremely dangerous and (probably) dumb.

    I wrote this as a proof-of-concept; it has not been extensively tested. Many
    potential side-effects are still unknown. As a general statement system call
    hooking is dangerous and the kernel goes to great lengths to prevent exactly
    what has been done here.

    There are glaring security implications involved in simply loading this
    module. Understand them throughly before using this if you even dare to use
    it at all.

    With those concerns stated, the main purpose of this module is to allow
    modification of privileges in-process by unprivileged users. It permits the
    definition of rules that allow processes to change user contexts without
    having to fork-exec something like su or sudo to "become" another user. A
    simple call to setuid(X) does the rest of the work for you, even if you're
    not root.

    Rules are inherited via procfs and may be modified freely at anytime.

    This module, in its present state, must be rebuilt for each unique kernel
    version to (at the very least) supply the address of the kernel's system
    call table. Supplying the wrong address will result in immediate kernel
    panic.
*/

#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/unistd.h>
#include <linux/version.h>

#define MODULE_NAME            "morph_module"
#define PROCFS_RULES_NAME      "morph_rules"
#define PROCFS_MAX_SIZE        4096
#define SYS_CALL_TABLE_ADDRESS 0xffffffff8028df40

MODULE_LICENSE("GPL"        );
MODULE_AUTHOR ("Matt Savona");
MODULE_VERSION("0.1"        );

void **sys_call_table = (void *)SYS_CALL_TABLE_ADDRESS;

struct m_rule {
  unsigned long s_id_low;
  unsigned long s_id_high;
  unsigned long d_id_low;
  unsigned long d_id_high;

  struct list_head list;
};

asmlinkage long (*o_setuid_sys_call)(uid_t uid);

struct proc_dir_entry *procfs_rules;
char procfs_rules_buffer[PROCFS_MAX_SIZE];
unsigned long procfs_rules_buffer_size = 0;

struct m_rule *current_m_rules;

void cleanup_rules(struct m_rule *rules) {
  struct m_rule *current_m_rule;
  struct list_head *cursor, *n;

  if(rules != NULL) {
    list_for_each_safe(cursor, n, &(rules->list)) {
      current_m_rule = list_entry(cursor, struct m_rule, list);
      list_del(cursor);
      kfree(current_m_rule);
    }
  }
}

int parse_rules(const char *buffer) {
  struct m_rule *current_m_rule, *next_m_rules, *tmp_m_rules = current_m_rules;

  char *rule;
  char *rule_lhs, *rule_rhs;
  char *source, *destination;
  char *source_range_lhs, *source_range_rhs;
  char *destination_range_lhs, *destination_range_rhs;
  char *tmp_buffer, *tmp_buffer_start_ptr;
  char *tmp_rule_rhs, *tmp_rule_rhs_start_ptr;
  char *endp;

  int rule_index = 0;

  if(buffer == NULL)
    return 0;

  /* Setup linked list */
  next_m_rules = (struct m_rule *)kmalloc(sizeof(struct m_rule), GFP_KERNEL);
  INIT_LIST_HEAD(&(next_m_rules->list)); 

  tmp_buffer = (char *)kmalloc(strlen(buffer) + 1, GFP_KERNEL);
  tmp_buffer_start_ptr = tmp_buffer;
  strcpy(tmp_buffer, buffer);

  /* Break up rules by whitespace first: */
  while((rule = strsep(&tmp_buffer, " \t\n"))) {
    if(strcmp(rule, "") == 0) continue;

    /* Now take a single rule and break it up by LHS and RHS on =: */
    rule_lhs = strsep(&rule, "=");
    rule_rhs = strsep(&rule, "=");

    if((rule_lhs != NULL && rule_rhs != NULL) &&
       (strcmp(rule_lhs, "") != 0 && strcmp(rule_rhs, "") != 0)) {

      /* For each comma delimited source ID: */
      while((source = strsep(&rule_lhs, ","))) {
        if(strcmp(source, "") == 0) continue;

        source_range_lhs = strsep(&source, "-");
        source_range_rhs = strsep(&source, "-");

        if(source_range_lhs == NULL || strcmp(source_range_lhs, "") == 0) continue;
        if(source_range_rhs == NULL || strcmp(source_range_rhs, "") == 0) source_range_rhs = source_range_lhs;

        /*  Make a temporary copy of all possible destinations: */
        tmp_rule_rhs = (char *)kmalloc(strlen(rule_rhs) + 1, GFP_KERNEL);
        tmp_rule_rhs_start_ptr = tmp_rule_rhs;
        strcpy(tmp_rule_rhs, rule_rhs);

        /* Break out each potential destination by ,: */
        while((destination = strsep(&tmp_rule_rhs, ","))) {
          if(strcmp(destination, "") == 0) continue;

          destination_range_lhs = strsep(&destination, "-");
          destination_range_rhs = strsep(&destination, "-");

          if(destination_range_lhs == NULL || strcmp(destination_range_lhs, "") == 0) continue;
          if(destination_range_rhs == NULL || strcmp(destination_range_rhs, "") == 0) destination_range_rhs = destination_range_lhs;

          current_m_rule = (struct m_rule *)kmalloc(sizeof(struct m_rule), GFP_KERNEL);
          current_m_rule->s_id_low  = simple_strtoul(source_range_lhs, &endp, 10);
          current_m_rule->s_id_high = simple_strtoul(source_range_rhs, &endp, 10);
          current_m_rule->d_id_low  = simple_strtoul(destination_range_lhs, &endp, 10);
          current_m_rule->d_id_high = simple_strtoul(destination_range_rhs, &endp, 10);

          list_add(&(current_m_rule->list), &(next_m_rules->list));

          rule_index++;
        }

        kfree(tmp_rule_rhs_start_ptr);
      }
    }
  }

  kfree(tmp_buffer_start_ptr);

  /* Swap the new rules into place and free up all the previously used rules */
  current_m_rules = next_m_rules;
  cleanup_rules(tmp_m_rules);

  return rule_index;
}

/*
  This is where all the magic happens: the setuid hook.

  The behavior was mostly copied from an article which (used to) reside:
    codenull.net/articles/kmh_en.html
*/
asmlinkage long n_setuid_sys_call(uid_t uid) {
  struct m_rule *current_m_rule;
  struct list_head *cursor;

  #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
    struct cred *cred = prepare_creds();
    if(cred->uid == 0) { return o_setuid_sys_call(uid); }

    list_for_each(cursor, &(current_m_rules->list)) {
      current_m_rule = list_entry(cursor, struct m_rule, list);

      if(cred->euid >= current_m_rule->s_id_low && cred->euid <= current_m_rule->s_id_high &&
         uid >= current_m_rule->d_id_low && uid <= current_m_rule->d_id_high) {
        cred->uid = cred->euid = cred->suid = cred->fsuid = uid;
        cred->gid = cred->egid = cred->sgid = cred->fsgid = uid;
        return commit_creds(cred);
      }
    }
  #else
    if(current->uid == 0) { return o_setuid_sys_call(uid); }

    list_for_each(cursor, &(current_m_rules->list)) {
      current_m_rule = list_entry(cursor, struct m_rule, list);

      if(current->euid >= current_m_rule->s_id_low && current->euid <= current_m_rule->s_id_high &&
         uid >= current_m_rule->d_id_low && uid <= current_m_rule->d_id_high) {

        current->uid = current->euid = current->suid = current->fsuid = uid;
        current->gid = current->egid = current->sgid = current->fsgid = uid;
        return 0;
      }
    }
  #endif

  return o_setuid_sys_call(uid);
}

/*
  disable_page_protection()/enable_page_protection() methods yanked from:
    http://stackoverflow.com/questions/2103315/linux-kernel-system-call-hooking-example/4000943#4000943

  But some further clarification about what they are doing (not documented on StackOverflow)...
    - See Intel Processor Manual Vol. 3A, page 2-20.
    - CR0 bit 16 is the Write-Protect bit.
    - Because the kernel's system call table is read-only, and we don't want to rebuild the kernel itself, we temporarily turn write protection off so we can hook our favorite system calls.
    - Attempting to make modifications to a RO page from within this kernel module will result in a kernel panic.
*/

void disable_page_protection(void) {
  unsigned long value;
  asm volatile("mov %%cr0,%0" : "=r" (value));
  if(value & 0x00010000) {
    value &= ~0x00010000;
    asm volatile("mov %0,%%cr0": : "r" (value));
  }
}

void enable_page_protection(void) {
  unsigned long value;
  asm volatile("mov %%cr0,%0" : "=r" (value));
  if(!(value & 0x00010000)) {
    value |= 0x00010000;
    asm volatile("mov %0,%%cr0": : "r" (value));
  }
}

int procfs_rules_read(char *buffer, char **buffer_location, off_t offset, int buffer_length, int *eof, void *data) {
  int return_value;

  if(offset > 0) {
    return_value = 0;
  } else {
    memcpy(buffer, procfs_rules_buffer, procfs_rules_buffer_size);
    return_value = procfs_rules_buffer_size;
  }

  return return_value;
}

int procfs_rules_write(struct file *file, const char *buffer, unsigned long count, void *data) {
  struct m_rule *current_m_rule;
  struct list_head *cursor;

  procfs_rules_buffer_size = count;
  if(procfs_rules_buffer_size > PROCFS_MAX_SIZE)
    procfs_rules_buffer_size = PROCFS_MAX_SIZE;

  if(copy_from_user(procfs_rules_buffer, buffer, procfs_rules_buffer_size))
    return -EFAULT;

  parse_rules(procfs_rules_buffer);

  printk(KERN_INFO "%s: setuid() rules have changed:\n", MODULE_NAME);
  list_for_each(cursor, &(current_m_rules->list)) {
    current_m_rule = list_entry(cursor, struct m_rule, list);
    printk(KERN_INFO "%s: %lu-%lu -> %lu-%lu\n", MODULE_NAME, 
           current_m_rule->s_id_low, 
           current_m_rule->s_id_high,
           current_m_rule->d_id_low,
           current_m_rule->d_id_high);
  }

  return procfs_rules_buffer_size;
}

int init_module(void) {
  current_m_rules = NULL;

  printk(KERN_INFO "Loading kernel module '%s'\n", MODULE_NAME);

  disable_page_protection();
  o_setuid_sys_call = sys_call_table[__NR_setuid];
  sys_call_table[__NR_setuid] = n_setuid_sys_call;
  enable_page_protection();

  procfs_rules = create_proc_entry(PROCFS_RULES_NAME, 0644, NULL);
  if(procfs_rules == NULL) {
    remove_proc_entry(PROCFS_RULES_NAME, &proc_root);
    printk(KERN_ALERT "Error: Could not initialize /proc/%s\n", PROCFS_RULES_NAME);
    return -ENOMEM;
  }

  procfs_rules->read_proc = procfs_rules_read;
  procfs_rules->write_proc = procfs_rules_write;
  procfs_rules->owner = THIS_MODULE;

  return 0;
}

void cleanup_module(void) {
  printk(KERN_INFO "Unloading kernel module '%s'\n", MODULE_NAME);

  disable_page_protection();
  sys_call_table[__NR_setuid] = o_setuid_sys_call;
  enable_page_protection();

  cleanup_rules(current_m_rules);
  remove_proc_entry(PROCFS_RULES_NAME, &proc_root);
}
