
'''

	Author:	Caleb Shortt
	Date:	January 2014

	Description:
		This module contains class(es) that assist with the dynamic 
		generation of HTML including attributes and more complex
		features

	NOTE:
		January 13, 2014:	This module is not being used anywhere

'''


class HTML_Attributes(object):
	'''
		This class contains methods that assist in dynamically generating
		valid HTML attributes for their associated tags

		-----------------------------------------------------------------
		Main Sources:

		https://developer.mozilla.org/en-US/docs/Web/HTML/Attributes

		-----------------------------------------------------------------

		General Method Template:

		def has<sttribute>(self, tag):
			if isinstance(tag, str):
				return tag.lower in [<list of tags>]
			return False
	'''

	def has_onload(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["body", "frame", "frameset", "iframe", 
								"img", "input", "link", "script", "style"]
		return False

	def has_accept(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["form", "input"]
		return False

	def has_accesskey(self, tag):
		'''
			Global Attribute
		'''
		return True

	def has_acceptcharset(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["form"]
		return False

	def has_action(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["form"]
		return False

	def has_align(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["applet", "caption", "col", "colgroup", "hr", 
								"iframe", "img", "table", "tbody", "td", 
								"tfoot", "th", "thead", "tr"]
		return False

	def has_alt(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["applet", "area", "img", "input"]
		return False

	def has_async(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["script"]
		return False

	def has_autocomplete(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["form", "input"]
		return False

	def has_autofocus(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["button", "input", "keygen", "select", 
								"textarea"]
		return False

	def has_autoplay(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["audio", "video"]
		return False

	def has_bgcolor(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["body", "col", "colgroup", "marquee", 
								"table", "tbody", "tfoot", "td", "th", "tr"]
		return False

	def has_border(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["img", "object", "table"]
		return False

	def has_buffered(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["audio", "video"]
		return False

	def has_challenge(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["keygen"]
		return False

	def has_charset(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["meta", "script"]
		return False

	def has_checked(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["command", "input"]
		return False

	def has_cite(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["blockquote", "del", "ins", "q"]
		return False

	def has_class(self, tag):
		'''
			Global Attribute
		'''
		return True

	def has_code(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["applet"]
		return False

	def has_codebase(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["applet"]
		return False

	def has_color(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["basefont", "font", "hr"]
		return False

	def has_cols(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["textarea"]
		return False

	def has_colspan(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["td", "th"]
		return False

	def has_content(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["meta"]
		return False

	def has_contenteditable(self, tag):
		return True

	def has_contextmenu(self, tag):
		return True

	def has_controls(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["audio", "video"]
		return False

	def has_coords(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["area"]
		return False

	def has_data(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["object"]
		return False

	'''
		Did not include the attribute data-*
	'''

	def has_datetime(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["del", "ins", "time"]
		return False

	def has_default(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["track"]
		return False

	def has_defer(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["script"]
		return False

	def has_dir(self, tag):
		return True

	def has_dirname(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["input", "textarea"]
		return False

	def has_disabled(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["button", "command", "fieldset", "input", 
								"keygen", "optgroup", "option", "select", 
								"textarea"]
		return False

	def has_download(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["a", "area"]
		return False

	def has_draggable(self, tag):
		return True

	def has_dropzone(self, tag):
		return True

	def has_enctype(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["form"]
		return False

	def has_for(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["label", "output"]
		return False

	def has_form(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["button", "fieldset", "input", "keygen", 
								"label", "meter", "object", "output", 
								"progress", "select", "textarea"]
		return False

	def has_headers(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["td, th"]
		return False

	def has_height(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["canvas", "embed", "iframe", "img", "input", 
								"object", "video"]
		return False

	def has_hidden(self, tag):
		return True

	def has_high(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["meter"]
		return False

	def has_href(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["a", "area", "base", "link"]
		return False

	def has_hreflang(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["a", "area", "link"]
		return False

	def has_httpequiv(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["meta"]
		return False

	def has_icon(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["command"]
		return False

	def has_id(self, tag):
		return True

	def has_ismap(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["img"]
		return False

	def has_itemprop(self, tag):
		return True

	def has_keytype(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["keygen"]
		return False

	def has_kind(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["track"]
		return False

	def has_label(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["track"]
		return False

	def has_lang(self, tag):
		return True

	def has_language(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["script"]
		return False

	def has_list(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["input"]
		return False

	def has_loop(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["audio", "bgsound", "marquee", "video"]
		return False

	def has_low(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["meter"]
		return False

	def has_manifest(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["html"]
		return False

	def has_max(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["input", "meter", "progress"]
		return False

	def has_maxlength(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["input", "textarea"]
		return False

	def has_media(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["a", "area", "link", "source", "style"]
		return False

	def has_method(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["form"]
		return False

	def has_min(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["input", "meter"]
		return False

	def has_multiple(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["input", "select"]
		return False

	def has_name(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["button", "form", "fieldset", "iframe", 
								"input", "keygen", "object", "output", 
								"select", "textarea", "map", "meta", "param"]
		return False

	def has_novalidate(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["form"]
		return False

	def has_open(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["details"]
		return False

	def has_optimum(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["meter"]
		return False

	def has_pattern(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["input"]
		return False

	def has_ping(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["a", "area"]
		return False

	def has_placeholder(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["input", "textarea"]
		return False

	def has_poster(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["video"]
		return False

	def has_preload(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["audio", "video"]
		return False

	def has_pubdate(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["time"]
		return False

	def has_radiogroup(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["command"]
		return False

	def has_readonly(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["input", "textarea"]
		return False

	def has_rel(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["a", "area", "link"]
		return False

	def has_required(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["input", "select", "textarea"]
		return False

	def has_reversed(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["ol"]
		return False

	def has_rows(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["textarea"]
		return False

	def has_rowspan(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["td", "th"]
		return False

	def has_sandbox(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["iframe"]
		return False

	def has_spellcheck(self, tag):
		return True

	def has_scope(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["th"]
		return False

	def has_scoped(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["style"]
		return False

	def has_seamless(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["iframe"]
		return False

	def has_selected(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["option"]
		return False

	def has_shape(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["a", "area"]
		return False

	def has_size(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["input", "select"]
		return False

	def has_sizes(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["link"]
		return False

	def has_span(self, tag):
		if isinstance(tag, str):
			return tag.lower in ["col", "colgroup"]
		return False







































