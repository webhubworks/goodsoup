<?php

namespace Webhubworks\Goodsoup\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Item extends Model {

    protected $guarded = [];

    protected $casts = [
        'is_newer_version_available' => 'boolean',
        'is_dev' => 'boolean',
        'is_abandoned' => 'boolean',
        'is_actively_maintained' => 'boolean',
    ];

    public function vulnerabilities(): HasMany
    {
        return $this->hasMany(Vulnerability::class);
    }
}