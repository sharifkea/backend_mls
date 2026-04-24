--
-- PostgreSQL database dump
--

-- Dumped from database version 14.7
-- Dumped by pg_dump version 14.7

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: add_group_member(bytea, uuid, integer, uuid); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.add_group_member(p_group_id bytea, p_user_id uuid, p_leaf_index integer, p_adder_user_id uuid) RETURNS boolean
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_is_member boolean;
    v_user_exists boolean;
BEGIN
    -- Check if adder is a member of the group
    SELECT EXISTS(
        SELECT 1 FROM group_members 
        WHERE group_id = p_group_id AND user_id = p_adder_user_id
    ) INTO v_is_member;
    
    IF NOT v_is_member THEN
        RAISE EXCEPTION 'User % is not a member of this group', p_adder_user_id;
    END IF;
    
    -- Check if user to add exists
    SELECT EXISTS(SELECT 1 FROM users WHERE user_id = p_user_id) INTO v_user_exists;
    
    IF NOT v_user_exists THEN
        RAISE EXCEPTION 'User % does not exist', p_user_id;
    END IF;
    
    -- Add new member
    INSERT INTO group_members (group_id, user_id, leaf_index)
    VALUES (p_group_id, p_user_id, p_leaf_index);
    
    -- Update group's last_updated
    UPDATE groups SET last_updated = NOW() WHERE group_id = p_group_id;
    
    RETURN TRUE;
EXCEPTION
    WHEN unique_violation THEN
        RAISE EXCEPTION 'User % is already a member of this group', p_user_id;
    WHEN others THEN
        RAISE;
END;
$$;


ALTER FUNCTION public.add_group_member(p_group_id bytea, p_user_id uuid, p_leaf_index integer, p_adder_user_id uuid) OWNER TO postgres;

--
-- Name: cleanup_old_key_packages(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.cleanup_old_key_packages() RETURNS integer
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_count integer;
BEGIN
    DELETE FROM key_packages
    WHERE expires_at < NOW()
       OR used = TRUE;

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$;


ALTER FUNCTION public.cleanup_old_key_packages() OWNER TO postgres;

--
-- Name: create_group(bytea, text, uuid, integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.create_group(p_group_id bytea, p_group_name text, p_creator_user_id uuid, p_cipher_suite integer) RETURNS boolean
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO groups (group_id, group_name, creator_user_id, cipher_suite, last_epoch)
    VALUES (p_group_id, p_group_name, p_creator_user_id, p_cipher_suite, 0);
    
    -- Add creator as first member (leaf index 0)
    INSERT INTO group_members (group_id, user_id, leaf_index)
    VALUES (p_group_id, p_creator_user_id, 0);
    
    RETURN TRUE;
EXCEPTION
    WHEN unique_violation THEN
        RAISE EXCEPTION 'Group with ID % already exists', encode(p_group_id, 'hex');
    WHEN others THEN
        RAISE;
END;
$$;


ALTER FUNCTION public.create_group(p_group_id bytea, p_group_name text, p_creator_user_id uuid, p_cipher_suite integer) OWNER TO postgres;

--
-- Name: delete_group(bytea, uuid); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.delete_group(p_group_id bytea, p_user_id uuid) RETURNS boolean
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_is_creator boolean;
BEGIN
    -- Check if user is the creator
    SELECT EXISTS(
        SELECT 1 FROM groups 
        WHERE group_id = p_group_id AND creator_user_id = p_user_id
    ) INTO v_is_creator;
    
    IF NOT v_is_creator THEN
        RAISE EXCEPTION 'Only the group creator can delete the group';
    END IF;
    
    -- Delete group (cascade will handle members, messages, secrets)
    DELETE FROM groups WHERE group_id = p_group_id;
    
    RETURN TRUE;
END;
$$;


ALTER FUNCTION public.delete_group(p_group_id bytea, p_user_id uuid) OWNER TO postgres;

--
-- Name: get_epoch_secret(bytea, integer, uuid); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.get_epoch_secret(p_group_id bytea, p_epoch integer, p_user_id uuid) RETURNS bytea
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_secret bytea;
BEGIN
    -- Verify user is a group member
    IF NOT EXISTS(
        SELECT 1 FROM group_members 
        WHERE group_id = p_group_id AND user_id = p_user_id AND is_active = TRUE
    ) THEN
        RAISE EXCEPTION 'User is not a member of this group';
    END IF;
    
    -- Get secret
    SELECT epoch_secret INTO v_secret
    FROM epoch_secrets
    WHERE group_id = p_group_id AND epoch = p_epoch;
    
    RETURN v_secret;
END;
$$;


ALTER FUNCTION public.get_epoch_secret(p_group_id bytea, p_epoch integer, p_user_id uuid) OWNER TO postgres;

--
-- Name: get_group_details(bytea); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.get_group_details(p_group_id bytea) RETURNS TABLE(group_id bytea, group_name text, creator_user_id uuid, creator_username text, cipher_suite integer, last_epoch integer, created_at timestamp with time zone, member_count bigint)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT 
        g.group_id,
        g.group_name,
        g.creator_user_id,
        u.username as creator_username,
        g.cipher_suite,
        g.last_epoch,
        g.created_at,
        COUNT(gm.user_id)::bigint as member_count
    FROM groups g
    JOIN users u ON g.creator_user_id = u.user_id
    LEFT JOIN group_members gm ON g.group_id = gm.group_id AND gm.is_active = TRUE
    WHERE g.group_id = p_group_id
    GROUP BY g.group_id, u.username;
END;
$$;


ALTER FUNCTION public.get_group_details(p_group_id bytea) OWNER TO postgres;

--
-- Name: get_group_messages(bytea, uuid, integer, integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.get_group_messages(p_group_id bytea, p_user_id uuid, p_since_epoch integer DEFAULT NULL::integer, p_limit integer DEFAULT 100) RETURNS TABLE(message_id uuid, group_id bytea, sender_user_id uuid, sender_username text, sender_leaf_index integer, epoch integer, ciphertext bytea, nonce bytea, content_type integer, created_at timestamp with time zone)
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_is_member boolean;
BEGIN
    -- Verify user is a group member (using table alias)
    SELECT EXISTS(
        SELECT 1 FROM group_members gm
        WHERE gm.group_id = p_group_id 
          AND gm.user_id = p_user_id 
          AND gm.is_active = TRUE
    ) INTO v_is_member;
    
    IF NOT v_is_member THEN
        RAISE EXCEPTION 'User is not a member of this group';
    END IF;
    
    RETURN QUERY
    SELECT 
        m.message_id,
        m.group_id,
        m.sender_user_id,
        u.username,
        m.sender_leaf_index,
        m.epoch,
        m.ciphertext,
        m.nonce,
        m.content_type,
        m.created_at
    FROM messages m
    JOIN users u ON m.sender_user_id = u.user_id
    WHERE m.group_id = p_group_id
        AND (p_since_epoch IS NULL OR m.epoch >= p_since_epoch)
    ORDER BY m.epoch ASC, m.created_at ASC
    LIMIT p_limit;
END;
$$;


ALTER FUNCTION public.get_group_messages(p_group_id bytea, p_user_id uuid, p_since_epoch integer, p_limit integer) OWNER TO postgres;

--
-- Name: get_latest_unused_key_package(uuid); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.get_latest_unused_key_package(p_user_id uuid) RETURNS TABLE(id uuid, ref_hash bytea, key_package bytea, created_at timestamp with time zone, expires_at timestamp with time zone)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT 
        kp.id, kp.ref_hash, kp.key_package, kp.created_at, kp.expires_at
    FROM key_packages kp
    WHERE kp.user_id = p_user_id
      AND kp.used = FALSE
      AND kp.expires_at > NOW()
    ORDER BY kp.created_at DESC
    LIMIT 1;
END;
$$;


ALTER FUNCTION public.get_latest_unused_key_package(p_user_id uuid) OWNER TO postgres;

--
-- Name: get_undelivered_messages(uuid); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.get_undelivered_messages(p_user_id uuid) RETURNS TABLE(message_id uuid, group_id bytea, sender_user_id uuid, sender_username text, epoch integer, ciphertext bytea, created_at timestamp with time zone)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT 
        m.message_id,
        m.group_id,
        m.sender_user_id,
        u.username as sender_username,
        m.epoch,
        m.ciphertext,
        m.created_at
    FROM messages m
    JOIN users u ON m.sender_user_id = u.user_id
    WHERE m.group_id IN (
        SELECT group_id FROM group_members 
        WHERE user_id = p_user_id AND is_active = TRUE
    )
    AND NOT (p_user_id::text = ANY(m.delivered_to))
    ORDER BY m.created_at ASC;
END;
$$;


ALTER FUNCTION public.get_undelivered_messages(p_user_id uuid) OWNER TO postgres;

--
-- Name: get_user_groups(uuid); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.get_user_groups(p_user_id uuid) RETURNS TABLE(group_id bytea, group_name text, last_epoch integer, member_count bigint, last_message_at timestamp with time zone)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT 
        g.group_id,
        g.group_name,
        g.last_epoch,
        COUNT(DISTINCT gm.user_id)::bigint as member_count,
        MAX(m.created_at) as last_message_at
    FROM groups g
    JOIN group_members gm ON g.group_id = gm.group_id
    LEFT JOIN messages m ON g.group_id = m.group_id
    WHERE gm.user_id = p_user_id AND gm.is_active = TRUE
    GROUP BY g.group_id, g.group_name, g.last_epoch;
END;
$$;


ALTER FUNCTION public.get_user_groups(p_user_id uuid) OWNER TO postgres;

--
-- Name: insert_key_package(uuid, bytea, bytea, timestamp with time zone); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.insert_key_package(p_user_id uuid, p_key_package bytea, p_ref_hash bytea, p_expires_at timestamp with time zone) RETURNS uuid
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_id uuid;
BEGIN
    -- First, deactivate ALL old active packages for this user
    UPDATE key_packages
    SET used = TRUE  -- Mark as used (inactive)
    WHERE user_id = p_user_id
      AND used = FALSE
      AND expires_at > NOW();
    
    -- Then insert the new package
    INSERT INTO key_packages (
        user_id, key_package, ref_hash, expires_at, created_at, used
    )
    VALUES (
        p_user_id,
        p_key_package,
        p_ref_hash,
        p_expires_at,
        NOW(),
        FALSE  -- This is the new active package
    )
    RETURNING id INTO v_id;

    RETURN v_id;
EXCEPTION
    WHEN unique_violation THEN
        RAISE EXCEPTION 'KeyPackage with ref_hash % already exists for user %', p_ref_hash, p_user_id;
    WHEN others THEN
        RAISE;
END;
$$;


ALTER FUNCTION public.insert_key_package(p_user_id uuid, p_key_package bytea, p_ref_hash bytea, p_expires_at timestamp with time zone) OWNER TO postgres;

--
-- Name: mark_key_package_used(bytea); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.mark_key_package_used(p_ref_hash bytea) RETURNS boolean
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_updated boolean := FALSE;
BEGIN
    UPDATE key_packages
    SET used = TRUE
    WHERE ref_hash = p_ref_hash
      AND used = FALSE
    RETURNING TRUE INTO v_updated;

    RETURN v_updated;
END;
$$;


ALTER FUNCTION public.mark_key_package_used(p_ref_hash bytea) OWNER TO postgres;

--
-- Name: mark_messages_delivered(bytea, uuid, uuid[]); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.mark_messages_delivered(p_group_id bytea, p_user_id uuid, p_message_ids uuid[]) RETURNS integer
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_count integer;
BEGIN
    WITH updated AS (
        UPDATE messages
        SET delivered_to = array_append(delivered_to, p_user_id::text)
        WHERE group_id = p_group_id 
          AND message_id = ANY(p_message_ids)
          AND NOT (p_user_id::text = ANY(delivered_to))
        RETURNING 1
    )
    SELECT COUNT(*) INTO v_count FROM updated;
    
    RETURN v_count;
END;
$$;


ALTER FUNCTION public.mark_messages_delivered(p_group_id bytea, p_user_id uuid, p_message_ids uuid[]) OWNER TO postgres;

--
-- Name: remove_group_member(bytea, uuid, uuid); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.remove_group_member(p_group_id bytea, p_user_id uuid, p_remover_user_id uuid) RETURNS boolean
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_is_member boolean;
    v_is_remover_member boolean;
BEGIN
    -- Check if remover is a member
    SELECT EXISTS(
        SELECT 1 FROM group_members 
        WHERE group_id = p_group_id AND user_id = p_remover_user_id AND is_active = TRUE
    ) INTO v_is_remover_member;
    
    IF NOT v_is_remover_member THEN
        RAISE EXCEPTION 'User % is not a member of this group', p_remover_user_id;
    END IF;
    
    -- Soft delete the member
    UPDATE group_members 
    SET is_active = FALSE 
    WHERE group_id = p_group_id AND user_id = p_user_id
    RETURNING TRUE INTO v_is_member;
    
    IF NOT v_is_member THEN
        RAISE EXCEPTION 'User % is not a member of this group', p_user_id;
    END IF;
    
    -- Update group timestamp
    UPDATE groups SET last_updated = NOW() WHERE group_id = p_group_id;
    
    RETURN TRUE;
END;
$$;


ALTER FUNCTION public.remove_group_member(p_group_id bytea, p_user_id uuid, p_remover_user_id uuid) OWNER TO postgres;

--
-- Name: store_epoch_secret(bytea, uuid, integer, bytea); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.store_epoch_secret(p_group_id bytea, p_user_id uuid, p_epoch integer, p_epoch_secret bytea) RETURNS jsonb
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_is_member     boolean;
    v_result        jsonb;
BEGIN
    -- 1. Check if the user is a member of the group
    SELECT EXISTS(
        SELECT 1 
        FROM group_members 
        WHERE group_id = p_group_id 
          AND user_id = p_user_id
    ) INTO v_is_member;

    IF NOT v_is_member THEN
        RETURN jsonb_build_object(
            'status', 'error',
            'message', 'Not a group member'
        );
    END IF;

    -- 2. Insert or update the epoch secret
    INSERT INTO epoch_secrets (group_id, epoch, epoch_secret, created_at)
    VALUES (p_group_id, p_epoch, p_epoch_secret, NOW())
    ON CONFLICT (group_id, epoch) 
    DO UPDATE SET 
        epoch_secret = EXCLUDED.epoch_secret,
        created_at   = NOW()
    RETURNING epoch INTO v_result;

    -- Return success
    RETURN jsonb_build_object(
        'status', 'stored',
        'epoch', p_epoch
    );

EXCEPTION
    WHEN OTHERS THEN
        RETURN jsonb_build_object(
            'status', 'error',
            'message', SQLERRM
        );
END;
$$;


ALTER FUNCTION public.store_epoch_secret(p_group_id bytea, p_user_id uuid, p_epoch integer, p_epoch_secret bytea) OWNER TO postgres;

--
-- Name: store_message(bytea, uuid, integer, bytea, bytea, integer, bytea, bytea, integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.store_message(p_group_id bytea, p_sender_user_id uuid, p_epoch integer, p_ciphertext bytea, p_nonce bytea, p_content_type integer, p_authenticated_data bytea DEFAULT '\x'::bytea, p_encrypted_sender_data bytea DEFAULT '\x'::bytea, p_wire_format integer DEFAULT 1) RETURNS uuid
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_message_id uuid;
    v_leaf_index integer;
    v_group_epoch integer;
BEGIN
    -- Get sender's leaf index
    SELECT leaf_index INTO v_leaf_index
    FROM group_members
    WHERE group_id = p_group_id AND user_id = p_sender_user_id AND is_active = TRUE;
    
    IF v_leaf_index IS NULL THEN
        RAISE EXCEPTION 'Sender is not a member of this group';
    END IF;
    
    -- Verify group epoch
    SELECT last_epoch INTO v_group_epoch
    FROM groups WHERE group_id = p_group_id;
    
    IF p_epoch != v_group_epoch THEN
        RAISE EXCEPTION 'Message epoch % does not match group epoch %', p_epoch, v_group_epoch;
    END IF;
    
    -- Insert message
    INSERT INTO messages (
        group_id, sender_user_id, sender_leaf_index, epoch,
        ciphertext, nonce, content_type, authenticated_data,
        encrypted_sender_data, wire_format
    ) VALUES (
        p_group_id, p_sender_user_id, v_leaf_index, p_epoch,
        p_ciphertext, p_nonce, p_content_type, p_authenticated_data,
        p_encrypted_sender_data, p_wire_format
    )
    RETURNING message_id INTO v_message_id;
    
    RETURN v_message_id;
END;
$$;


ALTER FUNCTION public.store_message(p_group_id bytea, p_sender_user_id uuid, p_epoch integer, p_ciphertext bytea, p_nonce bytea, p_content_type integer, p_authenticated_data bytea, p_encrypted_sender_data bytea, p_wire_format integer) OWNER TO postgres;

--
-- Name: store_message(bytea, uuid, integer, bytea, bytea, integer, bytea, bytea, integer, integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.store_message(p_group_id bytea, p_sender_user_id uuid, p_epoch integer, p_ciphertext bytea, p_nonce bytea, p_content_type integer, p_authenticated_data bytea, p_encrypted_sender_data bytea, p_wire_format integer, p_message_generation integer) RETURNS uuid
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_message_id UUID;
BEGIN
    INSERT INTO messages (
        group_id, 
        sender_user_id, 
        sender_leaf_index,
        epoch, 
        ciphertext, 
        nonce,
        content_type, 
        authenticated_data, 
        encrypted_sender_data,
        wire_format, 
        message_generation,  -- NEW COLUMN
        created_at
    ) VALUES (
        p_group_id, 
        p_sender_user_id, 
        NULL,  -- sender_leaf_index (will be filled by trigger or separately)
        p_epoch, 
        p_ciphertext, 
        p_nonce,
        p_content_type, 
        p_authenticated_data, 
        p_encrypted_sender_data,
        p_wire_format, 
        p_message_generation,  -- NEW VALUE
        NOW()
    )
    RETURNING message_id INTO v_message_id;
    
    RETURN v_message_id;
END;
$$;


ALTER FUNCTION public.store_message(p_group_id bytea, p_sender_user_id uuid, p_epoch integer, p_ciphertext bytea, p_nonce bytea, p_content_type integer, p_authenticated_data bytea, p_encrypted_sender_data bytea, p_wire_format integer, p_message_generation integer) OWNER TO postgres;

--
-- Name: store_message(bytea, uuid, integer, bytea, bytea, integer, bytea, bytea, integer, integer, integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.store_message(p_group_id bytea, p_sender_user_id uuid, p_epoch integer, p_ciphertext bytea, p_nonce bytea, p_content_type integer, p_authenticated_data bytea, p_encrypted_sender_data bytea, p_wire_format integer, p_message_generation integer, p_sender_leaf_index integer) RETURNS uuid
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_message_id UUID;
BEGIN
    INSERT INTO messages (
        group_id, 
        sender_user_id, 
        sender_leaf_index,  -- ← Now provided
        epoch, 
        ciphertext, 
        nonce,
        content_type, 
        authenticated_data, 
        encrypted_sender_data,
        wire_format, 
        message_generation, 
        created_at
    ) VALUES (
        p_group_id, 
        p_sender_user_id, 
        p_sender_leaf_index,  -- ← Use the parameter
        p_epoch, 
        p_ciphertext, 
        p_nonce,
        p_content_type, 
        p_authenticated_data, 
        p_encrypted_sender_data,
        p_wire_format, 
        p_message_generation, 
        NOW()
    )
    RETURNING message_id INTO v_message_id;
    
    RETURN v_message_id;
END;
$$;


ALTER FUNCTION public.store_message(p_group_id bytea, p_sender_user_id uuid, p_epoch integer, p_ciphertext bytea, p_nonce bytea, p_content_type integer, p_authenticated_data bytea, p_encrypted_sender_data bytea, p_wire_format integer, p_message_generation integer, p_sender_leaf_index integer) OWNER TO postgres;

--
-- Name: update_group_epoch(bytea, integer, uuid); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.update_group_epoch(p_group_id bytea, p_new_epoch integer, p_user_id uuid) RETURNS boolean
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_is_member boolean;
BEGIN
    -- Check if user is a member
    SELECT EXISTS(
        SELECT 1 FROM group_members 
        WHERE group_id = p_group_id AND user_id = p_user_id AND is_active = TRUE
    ) INTO v_is_member;
    
    IF NOT v_is_member THEN
        RAISE EXCEPTION 'User % is not a member of this group %', p_user_id, p_group_id;
    END IF;
    
    -- Update only the epoch, NO secret storage!
    UPDATE groups 
    SET last_epoch = p_new_epoch, last_updated = NOW() 
    WHERE group_id = p_group_id;
    
    RETURN TRUE;
END;
$$;


ALTER FUNCTION public.update_group_epoch(p_group_id bytea, p_new_epoch integer, p_user_id uuid) OWNER TO postgres;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: epoch_secrets; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.epoch_secrets (
    group_id bytea NOT NULL,
    epoch integer NOT NULL,
    epoch_secret bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.epoch_secrets OWNER TO postgres;

--
-- Name: group_members; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.group_members (
    group_id bytea NOT NULL,
    user_id uuid NOT NULL,
    leaf_index integer NOT NULL,
    joined_at timestamp with time zone DEFAULT now(),
    is_active boolean DEFAULT true
);


ALTER TABLE public.group_members OWNER TO postgres;

--
-- Name: groups; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.groups (
    group_id bytea NOT NULL,
    group_name text,
    creator_user_id uuid NOT NULL,
    cipher_suite integer NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    last_epoch integer DEFAULT 0,
    last_updated timestamp with time zone DEFAULT now(),
    is_active boolean DEFAULT true
);


ALTER TABLE public.groups OWNER TO postgres;

--
-- Name: key_packages; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.key_packages (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    key_package bytea NOT NULL,
    ref_hash bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    used boolean DEFAULT false
);


ALTER TABLE public.key_packages OWNER TO postgres;

--
-- Name: messages; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.messages (
    message_id uuid DEFAULT gen_random_uuid() NOT NULL,
    group_id bytea NOT NULL,
    sender_user_id uuid NOT NULL,
    sender_leaf_index integer NOT NULL,
    epoch integer NOT NULL,
    ciphertext bytea NOT NULL,
    nonce bytea NOT NULL,
    content_type integer NOT NULL,
    authenticated_data bytea DEFAULT '\x'::bytea,
    encrypted_sender_data bytea DEFAULT '\x'::bytea,
    wire_format integer NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    delivered_to text[] DEFAULT '{}'::text[]
);


ALTER TABLE public.messages OWNER TO postgres;

--
-- Name: pending_welcomes; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.pending_welcomes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    group_id bytea NOT NULL,
    to_user_id uuid NOT NULL,
    welcome bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    delivered boolean DEFAULT false
);


ALTER TABLE public.pending_welcomes OWNER TO postgres;

--
-- Name: users; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.users (
    user_id uuid DEFAULT gen_random_uuid() NOT NULL,
    username text NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    last_active timestamp with time zone DEFAULT now(),
    password_hash text NOT NULL
);


ALTER TABLE public.users OWNER TO postgres;

--
-- Name: epoch_secrets epoch_secrets_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.epoch_secrets
    ADD CONSTRAINT epoch_secrets_pkey PRIMARY KEY (group_id, epoch);


--
-- Name: group_members group_members_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.group_members
    ADD CONSTRAINT group_members_pkey PRIMARY KEY (group_id, user_id);


--
-- Name: groups groups_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_pkey PRIMARY KEY (group_id);


--
-- Name: key_packages key_packages_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.key_packages
    ADD CONSTRAINT key_packages_pkey PRIMARY KEY (id);


--
-- Name: key_packages key_packages_user_id_ref_hash_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.key_packages
    ADD CONSTRAINT key_packages_user_id_ref_hash_key UNIQUE (user_id, ref_hash);


--
-- Name: messages messages_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_pkey PRIMARY KEY (message_id);


--
-- Name: pending_welcomes pending_welcomes_group_id_to_user_id_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.pending_welcomes
    ADD CONSTRAINT pending_welcomes_group_id_to_user_id_key UNIQUE (group_id, to_user_id);


--
-- Name: pending_welcomes pending_welcomes_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.pending_welcomes
    ADD CONSTRAINT pending_welcomes_pkey PRIMARY KEY (id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (user_id);


--
-- Name: users users_username_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);


--
-- Name: idx_group_members_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_group_members_user_id ON public.group_members USING btree (user_id);


--
-- Name: idx_groups_creator; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_groups_creator ON public.groups USING btree (creator_user_id);


--
-- Name: idx_key_packages_expires_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_key_packages_expires_at ON public.key_packages USING btree (expires_at);


--
-- Name: idx_key_packages_unused; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_key_packages_unused ON public.key_packages USING btree (used) WHERE (used = false);


--
-- Name: idx_key_packages_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_key_packages_user_id ON public.key_packages USING btree (user_id);


--
-- Name: idx_messages_created_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_messages_created_at ON public.messages USING btree (created_at);


--
-- Name: idx_messages_epoch; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_messages_epoch ON public.messages USING btree (epoch);


--
-- Name: idx_messages_group_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_messages_group_id ON public.messages USING btree (group_id);


--
-- Name: epoch_secrets epoch_secrets_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.epoch_secrets
    ADD CONSTRAINT epoch_secrets_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.groups(group_id) ON DELETE CASCADE;


--
-- Name: group_members group_members_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.group_members
    ADD CONSTRAINT group_members_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.groups(group_id) ON DELETE CASCADE;


--
-- Name: group_members group_members_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.group_members
    ADD CONSTRAINT group_members_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


--
-- Name: groups groups_creator_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_creator_user_id_fkey FOREIGN KEY (creator_user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


--
-- Name: key_packages key_packages_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.key_packages
    ADD CONSTRAINT key_packages_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


--
-- Name: messages messages_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.groups(group_id) ON DELETE CASCADE;


--
-- Name: messages messages_group_id_sender_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_group_id_sender_user_id_fkey FOREIGN KEY (group_id, sender_user_id) REFERENCES public.group_members(group_id, user_id);


--
-- Name: messages messages_sender_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_sender_user_id_fkey FOREIGN KEY (sender_user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


--
-- Name: pending_welcomes pending_welcomes_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.pending_welcomes
    ADD CONSTRAINT pending_welcomes_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.groups(group_id) ON DELETE CASCADE;


--
-- Name: pending_welcomes pending_welcomes_to_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.pending_welcomes
    ADD CONSTRAINT pending_welcomes_to_user_id_fkey FOREIGN KEY (to_user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

