# Bash completion script for zcert
# Save this to a file and source it in your shell

# Installation instructions:
# 1. Generate completion script:
#    zcert config completion --shell bash > zcert-completion.bash
# 2. Source it in your current session:
#    source zcert-completion.bash
# 3. For permanent installation, add to your ~/.bashrc:
#    echo 'source /path/to/zcert-completion.bash' >> ~/.bashrc
# 4. Or install system-wide (requires sudo):
#    sudo cp zcert-completion.bash /etc/bash_completion.d/zcert

# bash completion for zcert                                -*- shell-script -*-

__zcert_debug()
{
    if [[ -n ${BASH_COMP_DEBUG_FILE:-} ]]; then
        echo "$*" >> "${BASH_COMP_DEBUG_FILE}"
    fi
}

# Homebrew on Macs have version 1.3 of bash-completion which doesn't include
# _init_completion. This is a very minimal version of that function.
__zcert_init_completion()
{
    COMPREPLY=()
    _get_comp_words_by_ref "$@" cur prev words cword
}

__zcert_index_of_word()
{
    local w word=$1
    shift
    index=0
    for w in "$@"; do
        [[ $w = "$word" ]] && return
        index=$((index+1))
    done
    index=-1
}

__zcert_contains_word()
{
    local w word=$1; shift
    for w in "$@"; do
        [[ $w = "$word" ]] && return
    done
    return 1
}

__zcert_handle_go_custom_completion()
{
    __zcert_debug "${FUNCNAME[0]}: cur is ${cur}, words[*] is ${words[*]}, #words[@] is ${#words[@]}"

    local shellCompDirectiveError=1
    local shellCompDirectiveNoSpace=2
    local shellCompDirectiveNoFileComp=4
    local shellCompDirectiveFilterFileExt=8
    local shellCompDirectiveFilterDirs=16

    local out requestComp lastParam lastChar comp directive args

    # Prepare the command to request completions for the program.
    # Calling ${words[0]} instead of directly zcert allows handling aliases
    args=("${words[@]:1}")
    # Disable ActiveHelp which is not supported for bash completion v1
    requestComp="ZCERT_ACTIVE_HELP=0 ${words[0]} __completeNoDesc ${args[*]}"

    lastParam=${words[$((${#words[@]}-1))]}
    lastChar=${lastParam:$((${#lastParam}-1)):1}
    __zcert_debug "${FUNCNAME[0]}: lastParam ${lastParam}, lastChar ${lastChar}"

    if [ -z "${cur}" ] && [ "${lastChar}" != "=" ]; then
        # If the last parameter is complete (there is a space following it)
        # We add an extra empty parameter so we can indicate this to the go method.
        __zcert_debug "${FUNCNAME[0]}: Adding extra empty parameter"
        requestComp="${requestComp} \"\""
    fi

    __zcert_debug "${FUNCNAME[0]}: calling ${requestComp}"
    # Use eval to handle any environment variables and such
    out=$(eval "${requestComp}" 2>/dev/null)

    # Extract the directive integer at the very end of the output following a colon (:)
    directive=${out##*:}
    # Remove the directive
    out=${out%:*}
    if [ "${directive}" = "${out}" ]; then
        # There is not directive specified
        directive=0
    fi
    __zcert_debug "${FUNCNAME[0]}: the completion directive is: ${directive}"
    __zcert_debug "${FUNCNAME[0]}: the completions are: ${out}"

    if [ $((directive & shellCompDirectiveError)) -ne 0 ]; then
        # Error code.  No completion.
        __zcert_debug "${FUNCNAME[0]}: received error from custom completion go code"
        return
    else
        if [ $((directive & shellCompDirectiveNoSpace)) -ne 0 ]; then
            if [[ $(type -t compopt) = "builtin" ]]; then
                __zcert_debug "${FUNCNAME[0]}: activating no space"
                compopt -o nospace
            fi
        fi
        if [ $((directive & shellCompDirectiveNoFileComp)) -ne 0 ]; then
            if [[ $(type -t compopt) = "builtin" ]]; then
                __zcert_debug "${FUNCNAME[0]}: activating no file completion"
                compopt +o default
            fi
        fi
    fi

    if [ $((directive & shellCompDirectiveFilterFileExt)) -ne 0 ]; then
        # File extension filtering
        local fullFilter filter filteringCmd
        # Do not use quotes around the $out variable or else newline
        # characters will be kept.
        for filter in ${out}; do
            fullFilter+="$filter|"
        done

        filteringCmd="_filedir $fullFilter"
        __zcert_debug "File filtering command: $filteringCmd"
        $filteringCmd
    elif [ $((directive & shellCompDirectiveFilterDirs)) -ne 0 ]; then
        # File completion for directories only
        local subdir
        # Use printf to strip any trailing newline
        subdir=$(printf "%s" "${out}")
        if [ -n "$subdir" ]; then
            __zcert_debug "Listing directories in $subdir"
            __zcert_handle_subdirs_in_dir_flag "$subdir"
        else
            __zcert_debug "Listing directories in ."
            _filedir -d
        fi
    else
        while IFS='' read -r comp; do
            COMPREPLY+=("$comp")
        done < <(compgen -W "${out}" -- "$cur")
    fi
}

__zcert_handle_reply()
{
    __zcert_debug "${FUNCNAME[0]}"
    local comp
    case $cur in
        -*)
            if [[ $(type -t compopt) = "builtin" ]]; then
                compopt -o nospace
            fi
            local allflags
            if [ ${#must_have_one_flag[@]} -ne 0 ]; then
                allflags=("${must_have_one_flag[@]}")
            else
                allflags=("${flags[*]} ${two_word_flags[*]}")
            fi
            while IFS='' read -r comp; do
                COMPREPLY+=("$comp")
            done < <(compgen -W "${allflags[*]}" -- "$cur")
            if [[ $(type -t compopt) = "builtin" ]]; then
                [[ "${COMPREPLY[0]}" == *= ]] || compopt +o nospace
            fi

            # complete after --flag=abc
            if [[ $cur == *=* ]]; then
                if [[ $(type -t compopt) = "builtin" ]]; then
                    compopt +o nospace
                fi

                local index flag
                flag="${cur%=*}"
                __zcert_index_of_word "${flag}" "${flags_with_completion[@]}"
                COMPREPLY=()
                if [[ ${index} -ge 0 ]]; then
                    PREFIX=""
                    cur="${cur#*=}"
                    ${flags_completion[${index}]}
                    if [ -n "${ZSH_VERSION:-}" ]; then
                        # zsh completion needs --flag= prefix
                        eval "COMPREPLY=( \"\${COMPREPLY[@]/#/${flag}=}\" )"
                    fi
                fi
            fi

            if [[ -z "${flag_parsing_disabled}" ]]; then
                # If flag parsing is enabled, we have completed the flags and can return.
                # If flag parsing is disabled, we may not know all (or any) of the flags, so we fallthrough
                # to possibly call handle_go_custom_completion.
                return 0;
            fi
            ;;
    esac

    # check if we are handling a flag with special work handling
    local index
    __zcert_index_of_word "${prev}" "${flags_with_completion[@]}"
    if [[ ${index} -ge 0 ]]; then
        ${flags_completion[${index}]}
        return
    fi

    # we are parsing a flag and don't have a special handler, no completion
    if [[ ${cur} != "${words[cword]}" ]]; then
        return
    fi

    local completions
    completions=("${commands[@]}")
    if [[ ${#must_have_one_noun[@]} -ne 0 ]]; then
        completions+=("${must_have_one_noun[@]}")
    elif [[ -n "${has_completion_function}" ]]; then
        # if a go completion function is provided, defer to that function
        __zcert_handle_go_custom_completion
    fi
    if [[ ${#must_have_one_flag[@]} -ne 0 ]]; then
        completions+=("${must_have_one_flag[@]}")
    fi
    while IFS='' read -r comp; do
        COMPREPLY+=("$comp")
    done < <(compgen -W "${completions[*]}" -- "$cur")

    if [[ ${#COMPREPLY[@]} -eq 0 && ${#noun_aliases[@]} -gt 0 && ${#must_have_one_noun[@]} -ne 0 ]]; then
        while IFS='' read -r comp; do
            COMPREPLY+=("$comp")
        done < <(compgen -W "${noun_aliases[*]}" -- "$cur")
    fi

    if [[ ${#COMPREPLY[@]} -eq 0 ]]; then
        if declare -F __zcert_custom_func >/dev/null; then
            # try command name qualified custom func
            __zcert_custom_func
        else
            # otherwise fall back to unqualified for compatibility
            declare -F __custom_func >/dev/null && __custom_func
        fi
    fi

    # available in bash-completion >= 2, not always present on macOS
    if declare -F __ltrim_colon_completions >/dev/null; then
        __ltrim_colon_completions "$cur"
    fi

    # If there is only 1 completion and it is a flag with an = it will be completed
    # but we don't want a space after the =
    if [[ "${#COMPREPLY[@]}" -eq "1" ]] && [[ $(type -t compopt) = "builtin" ]] && [[ "${COMPREPLY[0]}" == --*= ]]; then
       compopt -o nospace
    fi
}

# The arguments should be in the form "ext1|ext2|extn"
__zcert_handle_filename_extension_flag()
{
    local ext="$1"
    _filedir "@(${ext})"
}

__zcert_handle_subdirs_in_dir_flag()
{
    local dir="$1"
    pushd "${dir}" >/dev/null 2>&1 && _filedir -d && popd >/dev/null 2>&1 || return
}

__zcert_handle_flag()
{
    __zcert_debug "${FUNCNAME[0]}: c is $c words[c] is ${words[c]}"

    # if a command required a flag, and we found it, unset must_have_one_flag()
    local flagname=${words[c]}
    local flagvalue=""
    # if the word contained an =
    if [[ ${words[c]} == *"="* ]]; then
        flagvalue=${flagname#*=} # take in as flagvalue after the =
        flagname=${flagname%=*} # strip everything after the =
        flagname="${flagname}=" # but put the = back
    fi
    __zcert_debug "${FUNCNAME[0]}: looking for ${flagname}"
    if __zcert_contains_word "${flagname}" "${must_have_one_flag[@]}"; then
        must_have_one_flag=()
    fi

    # if you set a flag which only applies to this command, don't show subcommands
    if __zcert_contains_word "${flagname}" "${local_nonpersistent_flags[@]}"; then
      commands=()
    fi

    # keep flag value with flagname as flaghash
    # flaghash variable is an associative array which is only supported in bash > 3.
    if [[ -z "${BASH_VERSION:-}" || "${BASH_VERSINFO[0]:-}" -gt 3 ]]; then
        if [ -n "${flagvalue}" ] ; then
            flaghash[${flagname}]=${flagvalue}
        elif [ -n "${words[ $((c+1)) ]}" ] ; then
            flaghash[${flagname}]=${words[ $((c+1)) ]}
        else
            flaghash[${flagname}]="true" # pad "true" for bool flag
        fi
    fi

    # skip the argument to a two word flag
    if [[ ${words[c]} != *"="* ]] && __zcert_contains_word "${words[c]}" "${two_word_flags[@]}"; then
        __zcert_debug "${FUNCNAME[0]}: found a flag ${words[c]}, skip the next argument"
        c=$((c+1))
        # if we are looking for a flags value, don't show commands
        if [[ $c -eq $cword ]]; then
            commands=()
        fi
    fi

    c=$((c+1))

}

__zcert_handle_noun()
{
    __zcert_debug "${FUNCNAME[0]}: c is $c words[c] is ${words[c]}"

    if __zcert_contains_word "${words[c]}" "${must_have_one_noun[@]}"; then
        must_have_one_noun=()
    elif __zcert_contains_word "${words[c]}" "${noun_aliases[@]}"; then
        must_have_one_noun=()
    fi

    nouns+=("${words[c]}")
    c=$((c+1))
}

__zcert_handle_command()
{
    __zcert_debug "${FUNCNAME[0]}: c is $c words[c] is ${words[c]}"

    local next_command
    if [[ -n ${last_command} ]]; then
        next_command="_${last_command}_${words[c]//:/__}"
    else
        if [[ $c -eq 0 ]]; then
            next_command="_zcert_root_command"
        else
            next_command="_${words[c]//:/__}"
        fi
    fi
    c=$((c+1))
    __zcert_debug "${FUNCNAME[0]}: looking for ${next_command}"
    declare -F "$next_command" >/dev/null && $next_command
}

__zcert_handle_word()
{
    if [[ $c -ge $cword ]]; then
        __zcert_handle_reply
        return
    fi
    __zcert_debug "${FUNCNAME[0]}: c is $c words[c] is ${words[c]}"
    if [[ "${words[c]}" == -* ]]; then
        __zcert_handle_flag
    elif __zcert_contains_word "${words[c]}" "${commands[@]}"; then
        __zcert_handle_command
    elif [[ $c -eq 0 ]]; then
        __zcert_handle_command
    elif __zcert_contains_word "${words[c]}" "${command_aliases[@]}"; then
        # aliashash variable is an associative array which is only supported in bash > 3.
        if [[ -z "${BASH_VERSION:-}" || "${BASH_VERSINFO[0]:-}" -gt 3 ]]; then
            words[c]=${aliashash[${words[c]}]}
            __zcert_handle_command
        else
            __zcert_handle_noun
        fi
    else
        __zcert_handle_noun
    fi
    __zcert_handle_word
}

_zcert_config_completion()
{
    last_command="zcert_config_completion"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")
    local_nonpersistent_flags+=("--help")
    local_nonpersistent_flags+=("-h")
    flags+=("--shell=")
    two_word_flags+=("--shell")
    local_nonpersistent_flags+=("--shell")
    local_nonpersistent_flags+=("--shell=")
    flags+=("--config=")
    two_word_flags+=("--config")
    flags+=("--profile=")
    two_word_flags+=("--profile")
    flags+=("--verbose")

    must_have_one_flag=()
    must_have_one_flag+=("--shell=")
    must_have_one_noun=()
    noun_aliases=()
}

_zcert_config()
{
    last_command="zcert_config"

    command_aliases=()

    commands=()
    commands+=("completion")

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--cnf")
    local_nonpersistent_flags+=("--cnf")
    flags+=("--output=")
    two_word_flags+=("--output")
    local_nonpersistent_flags+=("--output")
    local_nonpersistent_flags+=("--output=")
    flags+=("--yaml")
    local_nonpersistent_flags+=("--yaml")
    flags+=("--config=")
    two_word_flags+=("--config")
    flags+=("--profile=")
    two_word_flags+=("--profile")
    flags+=("--verbose")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_zcert_enroll()
{
    last_command="zcert_enroll"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--bundle-file=")
    two_word_flags+=("--bundle-file")
    local_nonpersistent_flags+=("--bundle-file")
    local_nonpersistent_flags+=("--bundle-file=")
    flags+=("--cert-file=")
    two_word_flags+=("--cert-file")
    local_nonpersistent_flags+=("--cert-file")
    local_nonpersistent_flags+=("--cert-file=")
    flags+=("--chain-file=")
    two_word_flags+=("--chain-file")
    local_nonpersistent_flags+=("--chain-file")
    local_nonpersistent_flags+=("--chain-file=")
    flags+=("--cn=")
    two_word_flags+=("--cn")
    local_nonpersistent_flags+=("--cn")
    local_nonpersistent_flags+=("--cn=")
    flags+=("--country=")
    two_word_flags+=("--country")
    local_nonpersistent_flags+=("--country")
    local_nonpersistent_flags+=("--country=")
    flags+=("--csr=")
    two_word_flags+=("--csr")
    local_nonpersistent_flags+=("--csr")
    local_nonpersistent_flags+=("--csr=")
    flags+=("--csr-file=")
    two_word_flags+=("--csr-file")
    local_nonpersistent_flags+=("--csr-file")
    local_nonpersistent_flags+=("--csr-file=")
    flags+=("--format=")
    two_word_flags+=("--format")
    local_nonpersistent_flags+=("--format")
    local_nonpersistent_flags+=("--format=")
    flags+=("--hawk-id=")
    two_word_flags+=("--hawk-id")
    local_nonpersistent_flags+=("--hawk-id")
    local_nonpersistent_flags+=("--hawk-id=")
    flags+=("--hawk-key=")
    two_word_flags+=("--hawk-key")
    local_nonpersistent_flags+=("--hawk-key")
    local_nonpersistent_flags+=("--hawk-key=")
    flags+=("--key-curve=")
    two_word_flags+=("--key-curve")
    local_nonpersistent_flags+=("--key-curve")
    local_nonpersistent_flags+=("--key-curve=")
    flags+=("--key-file=")
    two_word_flags+=("--key-file")
    local_nonpersistent_flags+=("--key-file")
    local_nonpersistent_flags+=("--key-file=")
    flags+=("--key-password=")
    two_word_flags+=("--key-password")
    local_nonpersistent_flags+=("--key-password")
    local_nonpersistent_flags+=("--key-password=")
    flags+=("--key-size=")
    two_word_flags+=("--key-size")
    local_nonpersistent_flags+=("--key-size")
    local_nonpersistent_flags+=("--key-size=")
    flags+=("--key-type=")
    two_word_flags+=("--key-type")
    local_nonpersistent_flags+=("--key-type")
    local_nonpersistent_flags+=("--key-type=")
    flags+=("--locality=")
    two_word_flags+=("--locality")
    local_nonpersistent_flags+=("--locality")
    local_nonpersistent_flags+=("--locality=")
    flags+=("--no-key-output")
    local_nonpersistent_flags+=("--no-key-output")
    flags+=("--org=")
    two_word_flags+=("--org")
    local_nonpersistent_flags+=("--org")
    local_nonpersistent_flags+=("--org=")
    flags+=("--ou=")
    two_word_flags+=("--ou")
    local_nonpersistent_flags+=("--ou")
    local_nonpersistent_flags+=("--ou=")
    flags+=("--p12-password=")
    two_word_flags+=("--p12-password")
    local_nonpersistent_flags+=("--p12-password")
    local_nonpersistent_flags+=("--p12-password=")
    flags+=("--policy=")
    two_word_flags+=("--policy")
    local_nonpersistent_flags+=("--policy")
    local_nonpersistent_flags+=("--policy=")
    flags+=("--province=")
    two_word_flags+=("--province")
    local_nonpersistent_flags+=("--province")
    local_nonpersistent_flags+=("--province=")
    flags+=("--san-dns=")
    two_word_flags+=("--san-dns")
    local_nonpersistent_flags+=("--san-dns")
    local_nonpersistent_flags+=("--san-dns=")
    flags+=("--san-email=")
    two_word_flags+=("--san-email")
    local_nonpersistent_flags+=("--san-email")
    local_nonpersistent_flags+=("--san-email=")
    flags+=("--san-ip=")
    two_word_flags+=("--san-ip")
    local_nonpersistent_flags+=("--san-ip")
    local_nonpersistent_flags+=("--san-ip=")
    flags+=("--url=")
    two_word_flags+=("--url")
    local_nonpersistent_flags+=("--url")
    local_nonpersistent_flags+=("--url=")
    flags+=("--validity=")
    two_word_flags+=("--validity")
    local_nonpersistent_flags+=("--validity")
    local_nonpersistent_flags+=("--validity=")
    flags+=("--config=")
    two_word_flags+=("--config")
    flags+=("--profile=")
    two_word_flags+=("--profile")
    flags+=("--verbose")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_zcert_no-help()
{
    last_command="zcert_no-help"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--config=")
    two_word_flags+=("--config")
    flags+=("--profile=")
    two_word_flags+=("--profile")
    flags+=("--verbose")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_zcert_renew()
{
    last_command="zcert_renew"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--cn=")
    two_word_flags+=("--cn")
    local_nonpersistent_flags+=("--cn")
    local_nonpersistent_flags+=("--cn=")
    flags+=("--file=")
    two_word_flags+=("--file")
    local_nonpersistent_flags+=("--file")
    local_nonpersistent_flags+=("--file=")
    flags+=("--format=")
    two_word_flags+=("--format")
    local_nonpersistent_flags+=("--format")
    local_nonpersistent_flags+=("--format=")
    flags+=("--id=")
    two_word_flags+=("--id")
    local_nonpersistent_flags+=("--id")
    local_nonpersistent_flags+=("--id=")
    flags+=("--reuse-key")
    local_nonpersistent_flags+=("--reuse-key")
    flags+=("--serial=")
    two_word_flags+=("--serial")
    local_nonpersistent_flags+=("--serial")
    local_nonpersistent_flags+=("--serial=")
    flags+=("--config=")
    two_word_flags+=("--config")
    flags+=("--profile=")
    two_word_flags+=("--profile")
    flags+=("--verbose")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_zcert_retrieve()
{
    last_command="zcert_retrieve"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--chain")
    local_nonpersistent_flags+=("--chain")
    flags+=("--cn=")
    two_word_flags+=("--cn")
    local_nonpersistent_flags+=("--cn")
    local_nonpersistent_flags+=("--cn=")
    flags+=("--file=")
    two_word_flags+=("--file")
    local_nonpersistent_flags+=("--file")
    local_nonpersistent_flags+=("--file=")
    flags+=("--format=")
    two_word_flags+=("--format")
    local_nonpersistent_flags+=("--format")
    local_nonpersistent_flags+=("--format=")
    flags+=("--hawk-id=")
    two_word_flags+=("--hawk-id")
    local_nonpersistent_flags+=("--hawk-id")
    local_nonpersistent_flags+=("--hawk-id=")
    flags+=("--hawk-key=")
    two_word_flags+=("--hawk-key")
    local_nonpersistent_flags+=("--hawk-key")
    local_nonpersistent_flags+=("--hawk-key=")
    flags+=("--id=")
    two_word_flags+=("--id")
    local_nonpersistent_flags+=("--id")
    local_nonpersistent_flags+=("--id=")
    flags+=("--p12-password=")
    two_word_flags+=("--p12-password")
    local_nonpersistent_flags+=("--p12-password")
    local_nonpersistent_flags+=("--p12-password=")
    flags+=("--policy=")
    two_word_flags+=("--policy")
    local_nonpersistent_flags+=("--policy")
    local_nonpersistent_flags+=("--policy=")
    flags+=("--serial=")
    two_word_flags+=("--serial")
    local_nonpersistent_flags+=("--serial")
    local_nonpersistent_flags+=("--serial=")
    flags+=("--url=")
    two_word_flags+=("--url")
    local_nonpersistent_flags+=("--url")
    local_nonpersistent_flags+=("--url=")
    flags+=("--config=")
    two_word_flags+=("--config")
    flags+=("--profile=")
    two_word_flags+=("--profile")
    flags+=("--verbose")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_zcert_revoke()
{
    last_command="zcert_revoke"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--cn=")
    two_word_flags+=("--cn")
    local_nonpersistent_flags+=("--cn")
    local_nonpersistent_flags+=("--cn=")
    flags+=("--force")
    local_nonpersistent_flags+=("--force")
    flags+=("--hawk-id=")
    two_word_flags+=("--hawk-id")
    local_nonpersistent_flags+=("--hawk-id")
    local_nonpersistent_flags+=("--hawk-id=")
    flags+=("--hawk-key=")
    two_word_flags+=("--hawk-key")
    local_nonpersistent_flags+=("--hawk-key")
    local_nonpersistent_flags+=("--hawk-key=")
    flags+=("--id=")
    two_word_flags+=("--id")
    local_nonpersistent_flags+=("--id")
    local_nonpersistent_flags+=("--id=")
    flags+=("--reason=")
    two_word_flags+=("--reason")
    local_nonpersistent_flags+=("--reason")
    local_nonpersistent_flags+=("--reason=")
    flags+=("--serial=")
    two_word_flags+=("--serial")
    local_nonpersistent_flags+=("--serial")
    local_nonpersistent_flags+=("--serial=")
    flags+=("--url=")
    two_word_flags+=("--url")
    local_nonpersistent_flags+=("--url")
    local_nonpersistent_flags+=("--url=")
    flags+=("--config=")
    two_word_flags+=("--config")
    flags+=("--profile=")
    two_word_flags+=("--profile")
    flags+=("--verbose")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_zcert_search()
{
    last_command="zcert_search"

    command_aliases=()

    commands=()

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--cn=")
    two_word_flags+=("--cn")
    local_nonpersistent_flags+=("--cn")
    local_nonpersistent_flags+=("--cn=")
    flags+=("--expired")
    local_nonpersistent_flags+=("--expired")
    flags+=("--expiring=")
    two_word_flags+=("--expiring")
    local_nonpersistent_flags+=("--expiring")
    local_nonpersistent_flags+=("--expiring=")
    flags+=("--format=")
    two_word_flags+=("--format")
    local_nonpersistent_flags+=("--format")
    local_nonpersistent_flags+=("--format=")
    flags+=("--hawk-id=")
    two_word_flags+=("--hawk-id")
    local_nonpersistent_flags+=("--hawk-id")
    local_nonpersistent_flags+=("--hawk-id=")
    flags+=("--hawk-key=")
    two_word_flags+=("--hawk-key")
    local_nonpersistent_flags+=("--hawk-key")
    local_nonpersistent_flags+=("--hawk-key=")
    flags+=("--issuer=")
    two_word_flags+=("--issuer")
    local_nonpersistent_flags+=("--issuer")
    local_nonpersistent_flags+=("--issuer=")
    flags+=("--limit=")
    two_word_flags+=("--limit")
    local_nonpersistent_flags+=("--limit")
    local_nonpersistent_flags+=("--limit=")
    flags+=("--policy=")
    two_word_flags+=("--policy")
    local_nonpersistent_flags+=("--policy")
    local_nonpersistent_flags+=("--policy=")
    flags+=("--recent=")
    two_word_flags+=("--recent")
    local_nonpersistent_flags+=("--recent")
    local_nonpersistent_flags+=("--recent=")
    flags+=("--serial=")
    two_word_flags+=("--serial")
    local_nonpersistent_flags+=("--serial")
    local_nonpersistent_flags+=("--serial=")
    flags+=("--status=")
    two_word_flags+=("--status")
    local_nonpersistent_flags+=("--status")
    local_nonpersistent_flags+=("--status=")
    flags+=("--url=")
    two_word_flags+=("--url")
    local_nonpersistent_flags+=("--url")
    local_nonpersistent_flags+=("--url=")
    flags+=("--wide")
    local_nonpersistent_flags+=("--wide")
    flags+=("--config=")
    two_word_flags+=("--config")
    flags+=("--profile=")
    two_word_flags+=("--profile")
    flags+=("--verbose")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

_zcert_root_command()
{
    last_command="zcert"

    command_aliases=()

    commands=()
    commands+=("config")
    commands+=("enroll")
    commands+=("no-help")
    commands+=("renew")
    commands+=("retrieve")
    commands+=("revoke")
    commands+=("search")

    flags=()
    two_word_flags=()
    local_nonpersistent_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--config=")
    two_word_flags+=("--config")
    flags+=("--profile=")
    two_word_flags+=("--profile")
    flags+=("--verbose")

    must_have_one_flag=()
    must_have_one_noun=()
    noun_aliases=()
}

__start_zcert()
{
    local cur prev words cword split
    declare -A flaghash 2>/dev/null || :
    declare -A aliashash 2>/dev/null || :
    if declare -F _init_completion >/dev/null 2>&1; then
        _init_completion -s || return
    else
        __zcert_init_completion -n "=" || return
    fi

    local c=0
    local flag_parsing_disabled=
    local flags=()
    local two_word_flags=()
    local local_nonpersistent_flags=()
    local flags_with_completion=()
    local flags_completion=()
    local commands=("zcert")
    local command_aliases=()
    local must_have_one_flag=()
    local must_have_one_noun=()
    local has_completion_function=""
    local last_command=""
    local nouns=()
    local noun_aliases=()

    __zcert_handle_word
}

if [[ $(type -t compopt) = "builtin" ]]; then
    complete -o default -F __start_zcert zcert
else
    complete -o default -o nospace -F __start_zcert zcert
fi

# ex: ts=4 sw=4 et filetype=sh
